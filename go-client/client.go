/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"crypto/tls"
	"net/url"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// AmberClient is an interface which exposes methods for calling Amber REST APIs
type AmberClient interface {
	GetAmberCertificates() ([]byte, error)
	GetNonce() (*Nonce, error)
	GetToken(nonce *Nonce, policyIds []uuid.UUID, evidence *Evidence) (string, error)
	CollectToken(adapter EvidenceAdapter, policyIds []uuid.UUID) (string, error)
	VerifyToken(string) (*jwt.Token, error)
}

// EvidenceAdapter is an interface which exposes methods for collecting Quote using Adapter
type EvidenceAdapter interface {
	CollectEvidence(nonce []byte) (*Evidence, error)
}

// Evidence is used to store Quote to be sent for Attestation
type Evidence struct {
	Type     uint32
	Evidence []byte
	UserData []byte
	EventLog []byte
}

// Config holds the Amber configuration for Client
type Config struct {
	BaseUrl string
	TlsCfg  *tls.Config
	ApiUrl  string
	ApiKey  string
	url     *url.URL
}

// Nonce holds the signed nonce issued from Amber
type Nonce struct {
	Val       []byte `json:"val"`
	Iat       []byte `json:"iat"`
	Signature []byte `json:"signature"`
}

// New returns a new Amber API client instance
func New(cfg *Config) (AmberClient, error) {
	_, err := url.Parse(cfg.BaseUrl)
	if err != nil {
		return nil, err
	}

	cfg.url, err = url.Parse(cfg.ApiUrl)
	if err != nil {
		return nil, err
	}

	return &amberClient{
		cfg: cfg,
	}, nil
}

// amberClient manages communication with Amber V1 API
type amberClient struct {
	cfg *Config
}
