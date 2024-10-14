//go:build !test

/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

// The go-aztd package implements ITA evidence adapters by communicating with
// the Azure vTPM/paravisor.
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
	"github.com/intel/trustauthority-client/go-tpm"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// NewAzureTdxAdapter returns a legacy "EvidenceAdapter" that uses Azure's
// vTPM/paravisor implementation to collect TDX evidence.
func NewAzureTdxAdapter(tpmFactory tpm.TpmFactory, userData []byte) (connector.EvidenceAdapter, error) {
	return &azureTdxAdapter{
		userData:   userData,
		tpmFactory: tpmFactory,
	}, nil
}

// NewCompositeEvidenceAdapter returns an evidence adapter that uses Azure's
// vTPM/paravisor implementation to collect TDX evidence.
func NewCompositeEvidenceAdapter(tpmFactory tpm.TpmFactory) (connector.CompositeEvidenceAdapter, error) {
	return &azureTdxAdapter{
		tpmFactory: tpmFactory,
	}, nil
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
	userData   []byte
	tpmFactory tpm.TpmFactory
}

// CollectEvidence collects TDX evidence using Azure's vTPM/paravisor implementation.
func (a *azureTdxAdapter) CollectEvidence(nonce []byte) (*connector.Evidence, error) {

	if nonce == nil {
		nonce = []byte{}
	}

	tdxEvidence, err := getAzureTdxEvidence(a.tpmFactory, nonce, a.userData)
	if err != nil {
		return nil, err
	}

	return &connector.Evidence{
		Evidence:    tdxEvidence.Q,
		RuntimeData: tdxEvidence.R,
		UserData:    tdxEvidence.U,
	}, nil
}

// GetEvidenceIdentifier returns "tdx" for the Azure TDX adapter.
func (a *azureTdxAdapter) GetEvidenceIdentifier() string {
	return "tdx"
}

// GetEvidence returns TDX evidence using Azure's vTPM/paravisor implementation.
func (a *azureTdxAdapter) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (interface{}, error) {

	nonce := []byte{}
	if verifierNonce != nil {
		nonce = append(nonce, verifierNonce.Val...)
		nonce = append(nonce, verifierNonce.Iat...)
	}

	tdxEvidence, err := getAzureTdxEvidence(a.tpmFactory, nonce, userData)
	if err != nil {
		return nil, err
	}
	tdxEvidence.V = verifierNonce

	return tdxEvidence, nil
}

func getAzureTdxEvidence(tpmFactory tpm.TpmFactory, nonce []byte, userData []byte) (*tdxEvidence, error) {
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

	azRuntimeData, err := getAzRuntimeData(tpmFactory, reportDataHash, azRuntimeReadIdx, azRuntimeWriteIdx)
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

func getAzRuntimeData(tpmFactory tpm.TpmFactory, reportDataHash []byte, nvReadIdx int, nvWriteIdx int) (*azRuntimeData, error) {

	if len(reportDataHash) != 64 {
		return nil, errors.Errorf("Invalid report data hash size %d", len(reportDataHash))
	}

	// Azure TDX vTPMS use linux device and empty owner auth
	t, err := tpmFactory.New(tpm.TpmDeviceLinux, "")
	if err != nil {
		return nil, err
	}
	defer t.Close()

	if !t.NVExists(nvWriteIdx) {
		logrus.Infof("Initializing az nv index 0x%x", nvWriteIdx)
		err = t.NVDefine(nvWriteIdx, sha512.Size)
		if err != nil {
			return nil, errors.Wrapf(err, "NVDefine failed")
		}
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

	requestBody, err := json.Marshal(quoteReq)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(http.MethodPost, tdxReportUrl+"/acc/tdquote", bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/json")

	httpClient := http.DefaultClient
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, errors.Wrapf(err, "Request to %q failed", request.URL)
	}

	defer func() {
		err := response.Body.Close()
		if err != nil {
			errors.Errorf("Failed to close response body")
		}
	}()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Errorf("Failed to read response body: %s", err)
	}

	if response.StatusCode != http.StatusOK || response.ContentLength == 0 {
		return nil, errors.Errorf("Request to %q failed: StatusCode = %d, Body = %s", request.URL, response.StatusCode, string(body))
	}

	quoteResponse := struct {
		Quote string `json:"quote"`
	}{}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&quoteResponse)
	if err != nil {
		return nil, errors.Wrap(err, "Error unmarshalling quote response from azure")
	}

	tdxQuote, err := base64.RawURLEncoding.DecodeString(quoteResponse.Quote)
	if err != nil {
		return nil, errors.Wrap(err, "Error decoding quote from azure")
	}

	return tdxQuote, nil
}
