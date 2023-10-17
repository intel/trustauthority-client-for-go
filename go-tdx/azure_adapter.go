//go:build !test

/*
 *   Copyright (c) 2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strconv"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/pkg/errors"
)

// AzureAdapter manages TDX Quote collection from Azure TDX platform
type azureAdapter struct {
	uData       []byte
	EvLogParser EventLogParser
}

// NewEvidenceAdapter returns a new Azure Adapter instance
func NewEvidenceAdapter(udata []byte, evLogParser EventLogParser) (connector.EvidenceAdapter, error) {
	return &azureAdapter{
		uData:       udata,
		EvLogParser: evLogParser,
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

	hash := sha512.New()
	_, err := hash.Write(nonce)
	if err != nil {
		return nil, err
	}
	_, err = hash.Write(adapter.uData)
	if err != nil {
		return nil, err
	}
	reportData := hash.Sum(nil)

	tdReport, err := getTDReport(reportData)
	if err != nil {
		return nil, errors.Errorf("getTDReport returned err %v", err)
	}

	quote, err := getQuote(tdReport)
	if err != nil {
		return nil, errors.Errorf("getQuote returned error %v", err)
	}

	runtimeData, err := getRuntimeData()
	if err != nil {
		return nil, errors.Errorf("getRuntimeData returned error %v", err)
	}

	var eventLog []byte
	if adapter.EvLogParser != nil {
		rtmrEventLogs, err := adapter.EvLogParser.GetEventLogs()
		if err != nil {
			return nil, errors.Wrap(err, "There was an error while collecting RTMR Event Log Data")
		}

		eventLog, err = json.Marshal(rtmrEventLogs)
		if err != nil {
			return nil, errors.Wrap(err, "Error while marshalling RTMR Event Log Data")
		}
	}

	return &connector.Evidence{
		Type:     1,
		Evidence: quote,
		UserData: runtimeData,
		EventLog: eventLog,
	}, nil
}

func getTDReport(reportData []byte) ([]byte, error) {

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

	tdReport, err := exec.Command("tpm2_nvread", "-C", "o", "0x01400001", "--offset=32", "-s", "1024").Output()
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

func getRuntimeData() ([]byte, error) {

	size, err := exec.Command("tpm2_nvread", "-C", "o", "0x1400001", "--offset=1232", "-s", "4").Output()
	if err != nil {
		return nil, err
	}

	runtimeDataSize := binary.LittleEndian.Uint32(size)
	runtimeData, err := exec.Command("tpm2_nvread", "-C", "o", "0x01400001", "--offset=1236", "-s", strconv.Itoa(int(runtimeDataSize))).Output()
	if err != nil {
		return nil, err
	}
	return runtimeData, nil
}
