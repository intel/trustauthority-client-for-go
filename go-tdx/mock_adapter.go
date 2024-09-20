//go:build test

/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"github.com/intel/trustauthority-client/go-connector"
)

type mockAdapter struct {
	uData       []byte
	EvLogParser EventLogParser
}

func NewTdxAdapter(udata []byte, evLogParser EventLogParser) (connector.EvidenceAdapter, error) {
	return &mockAdapter{
		uData:       udata,
		EvLogParser: evLogParser,
	}, nil
}

func NewAzureTdxAdapter(udata []byte) (connector.EvidenceAdapter, error) {
	return &mockAdapter{
		uData: udata,
	}, nil
}

func (adapter *mockAdapter) CollectEvidence(nonce []byte) (*connector.Evidence, error) {

	return &connector.Evidence{
		Type:     1,
		Evidence: nil,
		UserData: nil,
		EventLog: nil,
	}, nil
}

func NewCompositeEvidenceAdapter(evLogParser EventLogParser) (connector.CompositeEvidenceAdapter, error) {
	return &mockAdapter2{}, nil
}

type mockAdapter2 struct{}

func (m *mockAdapter2) GetEvidenceIdentifier() string {
	return "tdx"
}

func (m *mockAdapter2) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (interface{}, error) {
	return &struct {
		R []byte                   `json:"runtime_data"`
		Q []byte                   `json:"quote"`
		U []byte                   `json:"user_data,omitempty"`
		V *connector.VerifierNonce `json:"verifier_nonce,omitempty"`
	}{
		R: make([]byte, 128),
		Q: make([]byte, 128),
		U: userData,
		V: verifierNonce,
	}, nil
}
