//go:build !test

/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

// #cgo LDFLAGS: -ltdx_attest -L/usr/lib/x86_64-linux-gnu/
//
// #include <stdlib.h>
// #include "tdx_attest.h"
import "C"
import (
	"crypto/sha512"
	"encoding/json"
	"unsafe"

	"github.com/intel/trustconnector/go-connector"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// CollectEvidence is used to get TDX quote using DCAP Quote Generation service
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

	cReportData := [64]C.uint8_t{}
	for i := 0; i < len(reportData); i++ {
		cReportData[i] = C.uint8_t(reportData[i])
	}

	// tdxReportData holds the reportdata provided as input from attested app
	tdxReportData := &C.tdx_report_data_t{d: cReportData}

	// selectedAttKeyId holds the default key id used for generating quote
	var selectedAttKeyId C.tdx_uuid_t

	var quoteSize C.uint32_t
	var quoteBuf *C.uint8_t

	ret := C.tdx_att_get_quote(tdxReportData, nil, 0, &selectedAttKeyId, &quoteBuf, &quoteSize, 0)
	if ret != 0 {
		return nil, errors.Errorf("tdx_att_get_quote return error code %x", ret)
	}

	quote := C.GoBytes(unsafe.Pointer(quoteBuf), C.int(quoteSize))

	ret = C.tdx_att_free_quote(quoteBuf)
	if ret != 0 {
		log.Warnf("tdx_att_free_quote return error code %x", ret)
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
		UserData: adapter.uData,
		EventLog: eventLog,
	}, nil
}
