package client

import (
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type clientImpl struct {
	apiKey   string
	amberUrl string
}

func New(apiKey string, amberUrl string) (AmberClient, error) {

	return &clientImpl{
		apiKey:   apiKey,
		amberUrl: amberUrl,
	}, nil
}

func (client *clientImpl) GetAmberVersion() (*Version, error) {
	return nil, errors.New("Not implmented:  Implement REST to retrieve version from AS")
}

func (client *clientImpl) GetNonce() (*SignedNonce, error) {
	return nil, errors.New("Not implmented:  Implement REST to retrieve nonce from AS")
}

func (client *clientImpl) GetToken(nonce *SignedNonce, policyIds []uuid.UUID, evidence Evidence) (*jwt.Token, error) {
	return nil, errors.New("Not implmented:  Implement REST to retrieve token from AS")
}

func (client *clientImpl) CollectToken(adapter EvidenceAdapter, policyIds []uuid.UUID) (*jwt.Token, error) {
	var nonce *SignedNonce
	var token *jwt.Token

	//nonce, err := client.GetNonce()

	evidence, err := adapter.CollectEvidence(nonce)
	if err != nil {
		return nil, errors.Errorf("Failed to collect evidence from adapter: %s", err)
	}

	fmt.Printf("EVD: %+v", evidence)

	//token, err := client.GetToken(nonce, policyIds, evidence)

	return token, nil
}
