//go:build !test

/*
 *   Copyright (c) 2023-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strings"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/pkg/errors"
)

const (
	TdReportOffset        = 32
	TdReportSize          = 1024
	RuntimeDataSizeOffset = 1232
	RuntimeDataOffset     = 1236
)

// AzureAdapter manages TDX Quote collection from Azure TDX platform
type azureAdapter struct {
	uData []byte
}

// NewAzureTdxAdapter returns a new Azure Adapter instance
func NewAzureTdxAdapter(udata []byte) (connector.EvidenceAdapter, error) {
	return &azureAdapter{
		uData: udata,
	}, nil
}

type QuoteRequest struct {
	Report string `json:"report"`
}

type QuoteResponse struct {
	Quote string `json:"quote"`
}

// CollectEvidence is used to get TDX quote using Azure Quote Generation service
func (adapter *azureAdapter) CollectEvidence(nonce []byte) (*connector.Evidence, error) {

	var reportData []byte
	if nonce != nil || adapter.uData != nil {
		hash := sha512.New()
		_, err := hash.Write(nonce)
		if err != nil {
			return nil, err
		}
		_, err = hash.Write(adapter.uData)
		if err != nil {
			return nil, err
		}
		reportData = hash.Sum(nil)
	} else {
		// zeroize the runtime_data.user-data
		reportData = make([]byte, 64)
	}

	tpmReport, err := getTDReport(reportData)
	if err != nil {
		return nil, errors.Errorf("getTDReport returned err %v", err)
	}
	tdReport := tpmReport[TdReportOffset : TdReportOffset+TdReportSize]

	quote, err := getQuote(tdReport)
	if err != nil {
		return nil, errors.Errorf("getQuote returned error %v", err)
	}

	runtimeDataSize := binary.LittleEndian.Uint32(tpmReport[RuntimeDataSizeOffset : RuntimeDataSizeOffset+4])
	runtimeData := tpmReport[RuntimeDataOffset : RuntimeDataOffset+runtimeDataSize]

	// validate the user-data(hash) in the evidence matches the user-data(hash) provided to the TPM
	var runtimeDataMap map[string]interface{}
	err = json.Unmarshal(runtimeData, &runtimeDataMap)
	if err != nil {
		return nil, errors.Errorf("invalid runtime_data %v", err)
	}
	userData, exists := runtimeDataMap["user-data"]
	if !exists {
		return nil, errors.Errorf("runtime_data doesn't include user-data %v", err)
	}
	userDataStr, ok := userData.(string)
	if !ok {
		return nil, errors.Errorf("user-data string assertion fail")
	}
	if !strings.EqualFold(userDataStr, hex.EncodeToString(reportData)) {
		return nil, errors.Errorf("The collected evidence is invalid")
	}

	return &connector.Evidence{
		Type:        connector.AzTdx,
		Evidence:    quote,
		UserData:    adapter.uData,
		RuntimeData: runtimeData,
	}, nil
}

func getTDReport(reportData []byte) ([]byte, error) {

	// check if index 0x01400002 is defined or not
	_, err := exec.Command("tpm2_nvreadpublic", "0x01400002").Output()
	if err != nil {
		_, err = exec.Command("tpm2_nvdefine", "-C", "o", "0x01400002", "-s", "64").Output()
		if err != nil {
			return nil, err
		}
	}
	cmd := exec.Command("tpm2_nvwrite", "-C", "o", "0x1400002", "-i", "-")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, string(reportData))
	}()

	_, err = cmd.Output()
	if err != nil {
		return nil, err
	}

	tdReport, err := exec.Command("tpm2_nvread", "-C", "o", "0x01400001").Output()
	if err != nil {
		return nil, err
	}
	return tdReport, nil
}

func getQuote(report []byte) ([]byte, error) {

	quoteReq := &QuoteRequest{
		Report: base64.URLEncoding.EncodeToString(report),
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

	var quoteRes QuoteResponse
	err = json.Unmarshal(response, &quoteRes)
	if err != nil {
		return nil, errors.Wrap(err, "Error unmarshalling Quote response from azure")
	}

	quote, err := base64.RawURLEncoding.DecodeString(quoteRes.Quote)
	if err != nil {
		return nil, errors.Wrap(err, "Error decoding Quote from azure")
	}
	return quote, nil
}
