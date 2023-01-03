//go:build test

/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tdx

import (
	"github.com/intel/amber/v1/client"
)

type MockTdxAdapter struct {
	uData       []byte
	EvLogParser EventLogParser
}

func NewAdapter(udata []byte, evLogParser EventLogParser) (*MockTdxAdapter, error) {
	return &MockTdxAdapter{
		uData:       udata,
		EvLogParser: evLogParser,
	}, nil
}

// CollectEvidence is used to get TDX quote using DCAP Quote Generation service
func (adapter *MockTdxAdapter) CollectEvidence(nonce []byte) (*client.Evidence, error) {

	return &client.Evidence{
		Type:     1,
		Evidence: nil,
		UserData: nil,
		EventLog: nil,
	}, nil
}
