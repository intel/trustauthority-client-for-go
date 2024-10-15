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
	// Build uses the state of the EvidenceBuilder (ex. evidence adapters, verifier
	// nonce, etc.) to build an evidence payload suitable for attestation by the
	// Trust Authority.
	Build() (interface{}, error)
}

type evidenceBuilder struct {
	adapters          []CompositeEvidenceAdapter
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

// WithEvidenceAdapter adds an EvidenceAdapter to the EvidenceBuilder.  The
// adapter is invoked during Build() to collect evidence.
func WithEvidenceAdapter(adapter CompositeEvidenceAdapter) EvidenceBuilderOption {
	return func(eb *evidenceBuilder) error {
		eb.adapters = append(eb.adapters, adapter)
		return nil
	}
}

// WithVerifierNonce sets the verifier nonce to be used when building evidence data.
func WithVerifierNonce(connector Connector) EvidenceBuilderOption {
	return func(eb *evidenceBuilder) error {
		requestId := uuid.New()
		nonceResponse, err := connector.GetNonce(GetNonceArgs{RequestId: requestId.String()})
		if err != nil {
			return errors.Wrapf(err, "Fai1ed to collect nonce from Trust Authority")
		}

		eb.verifierNonce = nonceResponse.Nonce
		return nil
	}
}

// WithPolicyIds sets the policy IDs that will be evaluated remotely by the Trust Authority.
func WithPolicyIds(policyIds []uuid.UUID) EvidenceBuilderOption {
	return func(eb *evidenceBuilder) error {
		eb.policyIds = policyIds
		return nil
	}
}

// WithUserData includes user defined data ('userData') into the attestation request's
// payload.  Evidence adapters are responsible for embedding hashes of the userData into
// evidence.  For example, the default TDX adapter includes a sha512 hash of the userData
// (along with the optional verifier nonce) into the 'report_data' field.  The Trust
// Authority's verifiers use the evidence to ensure the integrity of the userData and
// include it into the attestation token claim's 'attester_held_data' field.
func WithUserData(userData []byte) EvidenceBuilderOption {
	return func(eb *evidenceBuilder) error {
		eb.userData = userData
		return nil
	}
}

// WithPoliciesMustMatch determines whether the Trust Authority will fail if policies
// do not match.
func WithPoliciesMustMatch(policiesMustMatch bool) EvidenceBuilderOption {
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
