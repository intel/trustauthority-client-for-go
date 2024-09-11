/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

// EvidenceAdapter is an interface which exposes methods for collecting Quote from Platform
type EvidenceAdapter interface {
	CollectEvidence(nonce []byte) (*Evidence, error)
}

type EvidenceType int

const (
	Sgx EvidenceType = iota
	Tdx
	AzTdx
)

func (c EvidenceType) String() string {
	switch c {
	case Sgx:
		return "sgx"
	case Tdx:
		return "tdx"
	case AzTdx:
		return "aztdx"
	default:
		return "Unknown"
	}
}

// Evidence is used to store Quote to be sent for Attestation
type Evidence struct {
	Type        EvidenceType
	Evidence    []byte
	UserData    []byte
	EventLog    []byte
	RuntimeData []byte
}
