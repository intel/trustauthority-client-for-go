//go:build !test

/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package aztdx

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/tpm"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// NewAzureTdxAdapter returns a legacy "EvidenceAdapter" that uses Azure's
// vTPM/paravisor implementation to collect TDX evidence.
func NewAzureTdxAdapter(userData []byte) (connector.EvidenceAdapter, error) {
	return &azureTdxAdapter{
		userData: userData,
	}, nil
}

// NewCompositeEvidenceAdapter returns an evidence adapter that uses Azure's
// vTPM/paravisor implementation to collect TDX evidence.
func NewCompositeEvidenceAdapter() (connector.CompositeEvidenceAdapter, error) {
	return &azureTdxAdapter{}, nil
}

// tdxEvidence contains evidence returned by the Azure TDX adapter.
type tdxEvidence struct {
	R []byte                   `json:"runtime_data"`
	Q []byte                   `json:"quote"`
	U []byte                   `json:"user_data,omitempty"`
	V *connector.VerifierNonce `json:"verifier_nonce,omitempty"`
}

// azureTdxAdapter implements EvdiencerAdapter and CompositeEvidenceAdapter.  Both
// CollectEvidence and GetEvidence boil down to getAzureTdxEvidence.
type azureTdxAdapter struct {
	userData []byte
}

func (a *azureTdxAdapter) CollectEvidence(nonce []byte) (*connector.Evidence, error) {

	tdxEvidence, err := getAzureTdxEvidence(nonce, a.userData)
	if err != nil {
		return nil, err
	}

	return &connector.Evidence{
		Evidence:    tdxEvidence.Q,
		RuntimeData: tdxEvidence.R,
		UserData:    tdxEvidence.U,
	}, nil
}

func (a *azureTdxAdapter) GetEvidenceIdentifier() string {
	return "tdx"
}

func (a *azureTdxAdapter) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (interface{}, error) {

	nonce := []byte{}
	if verifierNonce != nil {
		nonce = append(nonce, verifierNonce.Val...)
		nonce = append(nonce, verifierNonce.Iat...)
	}

	tdxEvidence, err := getAzureTdxEvidence(nonce, userData)
	if err != nil {
		return nil, err
	}
	tdxEvidence.V = verifierNonce

	return tdxEvidence, nil
}

func getAzureTdxEvidence(nonce []byte, userData []byte) (*tdxEvidence, error) {
	reportData := [][]byte{}
	if nonce != nil {
		reportData = append(reportData, nonce)
	}

	if len(userData) != 0 {
		reportData = append(reportData, userData)
	}

	reportDataHash, err := getReportDataHash(reportData)
	if err != nil {
		return nil, err
	}

	azRuntimeData, err := getAzRuntimeData(reportDataHash, azRuntimeReadIdx, azRuntimeWriteIdx)
	if err != nil {
		return nil, err
	}

	// make sure the Azure rt-data's user-data field matches the report data
	rt, err := azRuntimeData.runtimeData()
	if err != nil {
		return nil, err
	}

	if strings.ToLower(hex.EncodeToString(reportDataHash)) != strings.ToLower(rt.UserData) {
		return nil, errors.New("The Azure runtime data's 'userdata' field does not match the report data.")
	}

	quote, err := getTdxQuote(azRuntimeData.tdReportBytes)
	if err != nil {
		return nil, err
	}

	tdxEvidence := tdxEvidence{
		R: azRuntimeData.runtimeJsonBytes,
		Q: quote,
		U: userData,
	}

	return &tdxEvidence, nil
}

func getReportDataHash(reportData [][]byte) ([]byte, error) {
	hash := sha512.New()

	if len(reportData) == 0 {
		return make([]byte, 64), nil // write zero's to nv-ram
	}

	for _, data := range reportData {
		_, err := hash.Write(data)
		if err != nil {
			return nil, err
		}
	}
	return hash.Sum(nil), nil
}

func getAzRuntimeData(reportDataHash []byte, nvReadIdx int, nvWriteIdx int) (*azRuntimeData, error) {

	if len(reportDataHash) != 64 {
		return nil, errors.Errorf("Invalid report data hash size %d", len(reportDataHash))
	}

	t, err := tpm.New()
	if err != nil {
		return nil, err
	}
	defer t.Close()

	if !t.NVExists(nvWriteIdx) {
		logrus.Infof("Initializing az nv index 0x%x", nvWriteIdx)
		t.NVDefine(nvWriteIdx, sha512.Size)
	}

	err = t.NVWrite(nvWriteIdx, reportDataHash)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to write report data to index 0x%x", nvWriteIdx)
	}

	runtimeDataBytes, err := t.NVRead(nvReadIdx)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to read runtime data at index 0x%x", nvReadIdx)
	}

	azRuntimeData, err := newAzRuntimeData(runtimeDataBytes)
	if err != nil {
		return nil, err
	}

	return azRuntimeData, nil
}

func getTdxQuote(tdReportBytes []byte) ([]byte, error) {
	quoteReq := struct {
		Report string `json:"report"`
	}{
		Report: base64.URLEncoding.EncodeToString(tdReportBytes),
	}

	body, err := json.Marshal(quoteReq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, "http://169.254.169.254/acc/tdquote", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	httpClient := http.DefaultClient
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "Request to %q failed", req.URL)
	}

	if resp != nil {
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				errors.Errorf("Failed to close response body")
			}
		}()
	}

	response, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Errorf("Failed to read response body: %s", err)
	}

	if resp.StatusCode != http.StatusOK || resp.ContentLength == 0 {
		return nil, errors.Errorf("Request to %q failed: StatusCode = %d, Response = %s", req.URL, resp.StatusCode, string(response))
	}

	quoteRes := struct {
		Quote string `json:"quote"`
	}{}

	err = json.Unmarshal(response, &quoteRes)
	if err != nil {
		return nil, errors.Wrap(err, "Error unmarshalling Quote response from azure")
	}

	tdxQuote, err := base64.RawURLEncoding.DecodeString(quoteRes.Quote)
	if err != nil {
		return nil, errors.Wrap(err, "Error decoding Quote from azure")
	}

	return tdxQuote, nil
}
