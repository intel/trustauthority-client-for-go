//go:build !test

/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"crypto/sha512"
	"encoding/json"

	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/pkg/errors"
)

// TdxAdapter manages TDX Quote collection from TDX enabled platform
type tdxAdapter struct {
	uData       []byte
	EvLogParser EventLogParser
}

// NewTdxAdapter returns a new TDX Adapter instance
func NewTdxAdapter(udata []byte, evLogParser EventLogParser) (connector.EvidenceAdapter, error) {
	return &tdxAdapter{
		uData:       udata,
		EvLogParser: evLogParser,
	}, nil
}

// CollectEvidence is used to get TDX quote using TDX Quote Generation service
func (adapter *tdxAdapter) CollectEvidence(nonce []byte) (*connector.Evidence, error) {

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

	_, err = linuxtsm.MakeClient()
	if err != nil {
		return nil, err
	}

	quote, err := getQuoteFromConfigFS(reportData)
	if err != nil {
		return nil, err
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
		Type:        connector.Tdx,
		Evidence:    quote,
		RuntimeData: adapter.uData,
		EventLog:    eventLog,
	}, nil
}

func getQuoteFromConfigFS(reportData []byte) ([]byte, error) {

	req := &report.Request{
		InBlob:     reportData[:],
		GetAuxBlob: false,
	}
	resp, err := linuxtsm.GetReport(req)
	if err != nil {
		return nil, err
	}

	return resp.OutBlob, nil
}
