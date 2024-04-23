/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// CompositeAdapter is an interface which exposes methods for building
// a (composite) evidence object that can be submitted to /appraisal/v2/attest
// for remote attestation.
type CompositeAdapter interface {
	GetEvidenceIdentifier() string
	GetEvidence(verifierNonce []byte, userData []byte) (interface{}, error)
}

type EvidenceBuilder interface {
	Build() (interface{}, error)
}

type evidenceBuilder struct {
	adapters      []CompositeAdapter
	verifierNonce *VerifierNonce
	userData      []byte
	policyIds     []uuid.UUID
}

type EvidenceBuilderOption func(*evidenceBuilder) error

func NewEvidenceBuilder(opts ...EvidenceBuilderOption) (EvidenceBuilder, error) {
	eb := &evidenceBuilder{}
	for _, opt := range opts {
		if err := opt(eb); err != nil {
			return nil, err
		}
	}

	if len(eb.adapters) == 0 {
		return nil, errors.New("At least one evidence type must be provided")
	}

	return eb, nil
}

func WithEvidenceAdapter(adapter CompositeAdapter) EvidenceBuilderOption {
	return func(eb *evidenceBuilder) error {
		eb.adapters = append(eb.adapters, adapter)
		return nil
	}
}

func WithVerifierNonce(connector Connector) EvidenceBuilderOption {
	return func(eb *evidenceBuilder) error {
		nonceResponse, err := connector.GetNonce(GetNonceArgs{RequestId: uuid.New().String()})
		if err != nil {
			return err
		}

		eb.verifierNonce = nonceResponse.Nonce
		return nil
	}
}

func WithPolicyIds(policyIds []uuid.UUID) EvidenceBuilderOption {
	return func(eb *evidenceBuilder) error {
		eb.policyIds = policyIds
		return nil
	}
}

func WithUserData(userData []byte) EvidenceBuilderOption {
	return func(eb *evidenceBuilder) error {
		eb.userData = userData
		return nil
	}
}

func (eb *evidenceBuilder) Build() (interface{}, error) {
	evidence := map[string]interface{}{}

	// Assume there are four possible combinations of verifier-nonce and user-data:
	// - None: no verifier-nonce or user-data (empty array)
	// - Just verifier-nonce (no user-data)
	// - Just user-data (no verifier-nonce)
	// - Both verifier-nonce and user-data
	//
	// The order will always be "verifier-nonce.Val" followed by "user-data".
	//
	// Meaning, this logic is coupled between the clients and the server.
	// A better solution would allow the clients to apply any number of "user-data"
	// elements (i.e., in any order).  As long as the server builds the hash in the
	// same order, the verification will succeed.
	//
	// This is a limitation of the current implementation.
	verifierNonce := []byte{}
	if eb.verifierNonce != nil {
		verifierNonce = eb.verifierNonce.Val
		evidence["verifier-nonce"] = eb.verifierNonce
	}

	for _, adapter := range eb.adapters {
		e, err := adapter.GetEvidence(verifierNonce, eb.userData)
		if err != nil {
			return nil, err
		}

		evidence[adapter.GetEvidenceIdentifier()] = e
	}

	return evidence, nil
}
