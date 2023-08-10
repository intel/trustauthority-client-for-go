//go:build test

/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"github.com/intel/amber-client/go-client"
)

type mockAdapter struct {
	uData       []byte
	EvLogParser EventLogParser
}

func NewEvidenceAdapter(udata []byte, evLogParser EventLogParser) (client.EvidenceAdapter, error) {
	return &mockAdapter{
		uData:       udata,
		EvLogParser: evLogParser,
	}, nil
}

func (adapter *mockAdapter) CollectEvidence(nonce []byte) (*client.Evidence, error) {

	return &client.Evidence{
		Type:     1,
		Evidence: nil,
		UserData: nil,
		EventLog: nil,
	}, nil
}
