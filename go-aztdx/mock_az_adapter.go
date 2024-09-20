//go:build test

/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package aztdx

import (
	"github.com/intel/trustauthority-client/go-connector"
)

func NewAzureTdxAdapter(userData []byte) (connector.EvidenceAdapter, error) {
	return &mockAzTdxAdapter{}, nil
}

func NewCompositeEvidenceAdapter() (connector.CompositeEvidenceAdapter, error) {
	return &mockAzTdxAdapter{}, nil
}

type mockAzTdxAdapter struct{}

func (m *mockAzTdxAdapter) GetEvidenceIdentifier() string {
	return "tdx"
}

func (m *mockAzTdxAdapter) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (interface{}, error) {
	return struct {
		R []byte                   `json:"runtime_data"`
		Q []byte                   `json:"quote"`
		U []byte                   `json:"user_data,omitempty"`
		V *connector.VerifierNonce `json:"verifier_nonce,omitempty"`
	}{
		R: make([]byte, 512),
		Q: make([]byte, 512),
		U: userData,
		V: verifierNonce,
	}, nil
}

func (adapter *mockAzTdxAdapter) CollectEvidence(nonce []byte) (*connector.Evidence, error) {

	return &connector.Evidence{
		Type:     1,
		Evidence: nil,
		UserData: nil,
		EventLog: nil,
	}, nil
}
