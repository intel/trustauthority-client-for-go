package client

import (
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

func (client *amberClient) CollectToken(adapter EvidenceAdapter, policyIds []uuid.UUID) (*jwt.Token, error) {

	nonce, err := client.GetNonce()
	if err != nil {
		return nil, errors.Errorf("Failed to collect nonce from Amber: %s", err)
	}

	evidence, err := adapter.CollectEvidence(nonce)
	if err != nil {
		return nil, errors.Errorf("Failed to collect evidence from adapter: %s", err)
	}

	token, err := client.GetToken(nonce, policyIds, evidence)
	if err != nil {
		return nil, errors.Errorf("Failed to collect token from Amber: %s", err)
	}

	return token, nil
}
