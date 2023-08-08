/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// CollectToken is used to initiate remote attestation from Amber
func (client *amberClient) CollectToken(adapter EvidenceAdapter, policyIds []uuid.UUID, reqId string) (string, map[string][]string, error) {

	nonce, headers, err := client.GetNonce(reqId)
	if err != nil {
		return "", headers, errors.Errorf("Failed to collect nonce from Amber: %s", err)
	}

	evidence, err := adapter.CollectEvidence(append(nonce.Val, nonce.Iat[:]...))
	if err != nil {
		return "", headers, errors.Errorf("Failed to collect evidence from adapter: %s", err)
	}

	token, headers, err := client.GetToken(nonce, policyIds, evidence, reqId)
	if err != nil {
		return "", headers, errors.Errorf("Failed to collect token from Amber: %s", err)
	}

	return token, headers, nil
}
