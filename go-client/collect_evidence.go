/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"github.com/pkg/errors"
)

// CollectToken is used to initiate remote attestation from Amber
func (client *amberClient) CollectToken(args CollectTokenArgs) (CollectTokenResponse, error) {

	var response CollectTokenResponse
	nonceResponse, err := client.GetNonce(GetNonceArgs{args.RequestId})
	response.Headers = nonceResponse.Headers
	if err != nil {
		return response, errors.Errorf("Failed to collect nonce from Amber: %s", err)
	}

	evidence, err := args.Adapter.CollectEvidence(append(nonceResponse.Nonce.Val, nonceResponse.Nonce.Iat[:]...))
	if err != nil {
		return response, errors.Errorf("Failed to collect evidence from adapter: %s", err)
	}

	tokenResponse, err := client.GetToken(GetTokenArgs{nonceResponse.Nonce, evidence, args.PolicyIds, args.RequestId})
	response.Token, response.Headers = tokenResponse.Token, tokenResponse.Headers
	if err != nil {
		return response, errors.Errorf("Failed to collect token from Amber: %s", err)
	}

	return response, nil
}
