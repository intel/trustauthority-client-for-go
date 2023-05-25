//go:build !test

/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"syscall"
	"unsafe"

	"github.com/intel/amber/v1/client"
	"github.com/pkg/errors"
)

// AzureAdapter manages TDX Quote collection from Azure enabled platform
type AzureAdapter struct {
	uData       []byte
	EvLogParser EventLogParser
}

// NewAzureAdapter returns a new Azure Adapter instance
func NewAzureAdapter(udata []byte, evLogParser EventLogParser) (*AzureAdapter, error) {
	return &AzureAdapter{
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

func IOC(dir, t, nr, size uintptr) uintptr {
	return (dir << IocDirshift) |
		(t << IocTypeShift) |
		(nr << IocNrShift) |
		(size << IocSizeShift)
}

func IOWR(t, nr, size uintptr) uintptr {
	return IOC(IocRead|IocWrite, t, nr, size)
}

func TdxCmdGetReportIO() uintptr {
	return IOWR('T', 1, TdxReportDataLen+TdxReportLen)
}

// CollectEvidence is used to get TDX quote using Azure Quote Generation service
func (adapter *AzureAdapter) CollectEvidence(nonce []byte) (*client.Evidence, error) {

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

	var tdrequest TdxReportRequest
	copy(tdrequest.ReportData[:], []byte(reportData))

	fd, err := syscall.Open(TdxAttestDevPath, syscall.O_RDWR|syscall.O_SYNC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)

	cmd := TdxCmdGetReportIO()
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&tdrequest)))
	if errno != 0 {
		return nil, syscall.Errno(errno)
	}

	report := make([]byte, TdReportSize)
	copy(report, tdrequest.TdReport[:])

	quote, err := getQuote(report)
	if err != nil {
		return nil, errors.Errorf("getQuote return error %v", err)
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

	return &client.Evidence{
		Type:     1,
		Evidence: quote,
		UserData: adapter.uData,
		EventLog: eventLog,
	}, nil
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
