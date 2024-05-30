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
	GetEvidence(verifierNonce *VerifierNonce, userData []byte) (interface{}, error)
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

	for _, adapter := range eb.adapters {
		e, err := adapter.GetEvidence(eb.verifierNonce, eb.userData)
		if err != nil {
			return nil, err
		}

		evidence[adapter.GetEvidenceIdentifier()] = e
	}

	return evidence, nil
}
