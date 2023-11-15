/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"github.com/pkg/errors"
)

// Attest is used to initiate remote attestation with Trust Authority
func (connector *trustAuthorityConnector) Attest(args AttestArgs) (AttestResponse, error) {

	var response AttestResponse
	nonceResponse, err := connector.GetNonce(GetNonceArgs{args.RequestId})
	response.Headers = nonceResponse.Headers
	if err != nil {
		return response, errors.Errorf("Failed to collect nonce from Trust Authority: %s", err)
	}

	evidence, err := args.Adapter.CollectEvidence(append(nonceResponse.Nonce.Val, nonceResponse.Nonce.Iat[:]...))
	if err != nil {
		return response, errors.Errorf("Failed to collect evidence from adapter: %s", err)
	}

	tokenResponse, err := connector.GetToken(GetTokenArgs{nil, evidence, args.PolicyIds, args.RequestId, args.TokenSigningAlg, args.PolicyMustMatch})
	response.Token, response.Headers = tokenResponse.Token, tokenResponse.Headers
	if err != nil {
		return response, errors.Errorf("Failed to collect token from Trust Authority: %s", err)
	}

	return response, nil
}
