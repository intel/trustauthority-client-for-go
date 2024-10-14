//go:build test

/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"github.com/intel/trustauthority-client/go-connector"
)

// This file is required by the tdx-cli unit tests and will be removed in CASSINI-23218.

type TpmAdapterOptions func(*mockTpmAdapter) error

// NewCompositeEvidenceAdapterWithOptions creates a new composite adapter for the host's TPM.
func NewCompositeEvidenceAdapterWithOptions(opts ...TpmAdapterOptions) (connector.CompositeEvidenceAdapter, error) {
	return &mockTpmAdapter{}, nil
}

type mockTpmAdapter struct{}

func (m *mockTpmAdapter) GetEvidenceIdentifier() string {
	return "tpm"
}

func (m *mockTpmAdapter) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (interface{}, error) {
	return struct {
		Q []byte                   `json:"quote"`
		S []byte                   `json:"signature"`
		P []byte                   `json:"pcrs"`
		U []byte                   `json:"user_data,omitempty"`
		V *connector.VerifierNonce `json:"verifier_nonce,omitempty"`
	}{
		Q: make([]byte, 64),
		S: make([]byte, 64),
		P: make([]byte, 64),
		U: userData,
		V: verifierNonce,
	}, nil
}

func WithOwnerAuth(ownerAuth string) TpmAdapterOptions {
	return func(tca *mockTpmAdapter) error { return nil }
}

func WithAkHandle(akHandle int) TpmAdapterOptions {
	return func(tca *mockTpmAdapter) error { return nil }
}

func WithPcrSelections(selections string) TpmAdapterOptions {
	return func(tca *mockTpmAdapter) error { return nil }
}

func WithImaLogs(imaLogsPath string) TpmAdapterOptions {
	return func(tca *mockTpmAdapter) error { return nil }
}

func WithUefiEventLogs(eventLogsPath string) TpmAdapterOptions {
	return func(tca *mockTpmAdapter) error { return nil }
}
