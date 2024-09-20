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

// CompositeEvidenceAdapter is an interface that facilitates the collection of composite
// attestation requests (i.e., that have multiple evidence types like TDX+TPM).
// It abstracts the collection of a host's evidence in conjunction with EvidenceBuilder.
type CompositeEvidenceAdapter interface {
	// GetEvidenceIdentifier returns a unique string identifier for the evidence type.
	// For example, "tdx" or "tpm".  This identifier is when constructing the attestation
	// request's payload (ex. { "tpm": { evidence...}, "tdx": { evidence...}})
	GetEvidenceIdentifier() string

	// The implementor of EvidenceAdapter must implement this method and return
	// a JSON serializable interface{} of the attestation request.
	//
	// When not nil, the 'veriferNonce' must be included in resulting interface and be
	// cryptographically bound to the evidence (i.e. hashed into the TDX quote's report
	// data).
	//
	// When not nil, the 'userData' must also be included in the resulting interface
	// and hashed in the evidence.  User data is often used for including data such
	// as a public encrypt key to a relying party.
	//
	// The hashing algorithm for the verifier-nonce and user-data is evidence type specific
	// and verified by the Trust Authority.  For example, some evidence types may only
	// provide 32 bytes for the hash (in which case SHA256 should be used). When possible,
	// 64 bytes (SHA512) is recommended.
	//
	// Assuming hash 'h', the verifier-nonce and user-data should be hashed as follows:
	// - if neither verifier-nonce or user-data is provided:  an array of zero's "h.Size()"
	// - if only verifier-nonce is provided:  h(verifier-nonce.Val|verifier-nonce.Iat)
	// - if only user-data is provided:  h(user-data)
	// - if both verifier-nonce and user-data are provided:  h(verifier-nonce.Val|verifier-nonce.Iat|user-data)
	GetEvidence(verifierNonce *VerifierNonce, userData []byte) (interface{}, error)
}
