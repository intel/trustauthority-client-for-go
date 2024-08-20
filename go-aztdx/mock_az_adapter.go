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

// NewAzureTdxAdapter returns an evidence adapter that uses Azure's
// vTPM/paravisor implementation to collect TDX evidence.
func NewAzureTdxAdapter() (connector.EvidenceAdapter2, error) {
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
