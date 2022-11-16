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
func (client *amberClient) CollectToken(adapter EvidenceAdapter, policyIds []uuid.UUID) ([]byte, error) {

	nonce, err := client.GetNonce()
	if err != nil {
		return nil, errors.Errorf("Failed to collect nonce from Amber: %s", err)
	}

	evidence, err := adapter.CollectEvidence(append(nonce.Val, nonce.Iat[:]...))
	if err != nil {
		return nil, errors.Errorf("Failed to collect evidence from adapter: %s", err)
	}

	token, err := client.GetToken(nonce, policyIds, evidence)
	if err != nil {
		return nil, errors.Errorf("Failed to collect token from Amber: %s", err)
	}

	return token, nil
}
