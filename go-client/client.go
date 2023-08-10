/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"crypto/tls"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// AmberClient is an interface which exposes methods for calling Amber REST APIs
type AmberClient interface {
	GetAmberCertificates() ([]byte, error)
	GetNonce(GetNonceArgs) (GetNonceResponse, error)
	GetToken(GetTokenArgs) (GetTokenResponse, error)
	CollectToken(CollectTokenArgs) (CollectTokenResponse, error)
	VerifyToken(string) (*jwt.Token, error)
}

// EvidenceAdapter is an interface which exposes methods for collecting Quote from Platform
type EvidenceAdapter interface {
	CollectEvidence(nonce []byte) (*Evidence, error)
}

// GetNonceArgs holds the request parameters needed for getting nonce from Amber
type GetNonceArgs struct {
	RequestId string
}

// GetNonceResponse holds the response parameters recieved from nonce endpoint
type GetNonceResponse struct {
	Nonce   *VerifierNonce
	Headers http.Header
}

// GetTokenArgs holds the request parameters needed for getting token from Amber
type GetTokenArgs struct {
	Nonce     *VerifierNonce
	Evidence  *Evidence
	PolicyIds []uuid.UUID
	RequestId string
}

// GetTokenResponse holds the response parameters recieved from attest endpoint
type GetTokenResponse struct {
	Token   string
	Headers http.Header
}

// CollectTokenArgs holds the request parameters needed for attestation with Amber
type CollectTokenArgs struct {
	Adapter   EvidenceAdapter
	PolicyIds []uuid.UUID
	RequestId string
}

// CollectTokenResponse holds the response parameters recieved during attestation flow
type CollectTokenResponse struct {
	Token   string
	Headers http.Header
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

// VerifierNonce holds the signed nonce issued from Amber
type VerifierNonce struct {
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
