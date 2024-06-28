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

// EvidenceBuilder is a utility for creating attestation evidence
// request payloads.
type EvidenceBuilder interface {
	Build() (interface{}, error)
}

type evidenceBuilder struct {
	adapters          []EvidenceAdapter2
	verifierNonce     *VerifierNonce
	userData          []byte
	policyIds         []uuid.UUID
	tokenSigningAlg   JwtAlg
	policiesMustMatch bool
}

type EvidenceBuilderOption func(*evidenceBuilder) error

// NewEvidenceBuilder creates a new EvidenceBuilder instance with the
// specified options.
func NewEvidenceBuilder(opts ...EvidenceBuilderOption) (EvidenceBuilder, error) {
	eb := &evidenceBuilder{
		tokenSigningAlg:   "",
		policiesMustMatch: false,
	}

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

func WithEvidenceAdapter(adapter EvidenceAdapter2) EvidenceBuilderOption {
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

func WithPolicyMustMatch(policiesMustMatch bool) EvidenceBuilderOption {
	return func(eb *evidenceBuilder) error {
		eb.policiesMustMatch = policiesMustMatch
		return nil
	}
}

// WithTokenSigningAlgorithm determines which signing algorithm will
// be applied when ITA creates an attestation token.
func WithTokenSigningAlgorithm(tokenSigningAlg JwtAlg) EvidenceBuilderOption {
	return func(eb *evidenceBuilder) error {
		eb.tokenSigningAlg = tokenSigningAlg
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

	// add common, top level request parameters (when present)
	if len(eb.policyIds) > 0 {
		evidence["policy_ids"] = eb.policyIds
	}

	if eb.policiesMustMatch {
		evidence["policy_must_match"] = eb.policiesMustMatch
	}

	if eb.tokenSigningAlg != "" {
		evidence["token_signing_alg"] = eb.tokenSigningAlg
	}

	return evidence, nil
}
