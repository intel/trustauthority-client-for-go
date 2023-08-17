/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"context"
	"crypto/tls"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"strings"
	"time"

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

// RetryConfig a retryable client configuration for automatic retries to tolerate minor outages.
type RetryConfig struct {
	RetryWaitMin *time.Duration // Minimum time to wait
	RetryWaitMax *time.Duration // Maximum time to wait
	RetryMax     *int           // Maximum number of retries

	CheckForRetry retryablehttp.CheckRetry
	BackOff       retryablehttp.Backoff
}

// Config holds the Amber configuration for Client
type Config struct {
	BaseUrl string
	TlsCfg  *tls.Config
	ApiUrl  string
	ApiKey  string
	url     *url.URL
	*RetryConfig
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

	retryableClient := retryablehttp.NewClient()
	retryableClient.CheckRetry = defaultRetryPolicy
	retryableClient.RetryWaitMax = DefaultRetryWaitMaxSeconds * time.Second
	retryableClient.RetryWaitMin = DefaultRetryWaitMinSeconds * time.Second
	retryableClient.RetryMax = MaxRetries
	retryableClient.Logger = logrus.StandardLogger()
	if cfg.RetryConfig == nil {
		return &amberClient{
			cfg:     cfg,
			rclient: retryableClient,
		}, nil
	}

	if cfg.RetryConfig.CheckForRetry != nil {
		retryableClient.CheckRetry = cfg.RetryConfig.CheckForRetry
	}
	if cfg.RetryConfig.RetryWaitMax != nil {
		retryableClient.RetryWaitMax = *cfg.RetryConfig.RetryWaitMax
	}
	if cfg.RetryConfig.RetryWaitMin != nil {
		retryableClient.RetryWaitMin = *cfg.RetryConfig.RetryWaitMin
	}
	if cfg.RetryConfig.RetryMax != nil {
		retryableClient.RetryMax = *cfg.RetryConfig.RetryMax
	}
	if cfg.RetryConfig.BackOff != nil {
		retryableClient.Backoff = cfg.RetryConfig.BackOff
	}

	return &amberClient{
		cfg:     cfg,
		rclient: retryableClient,
	}, nil
}

// amberClient manages communication with Amber V1 API
type amberClient struct {
	cfg     *Config
	rclient *retryablehttp.Client
}

var retryableStatusCode = map[int]bool{
	500: true,
	503: true,
	504: true,
}

func defaultRetryPolicy(ctx context.Context, resp *http.Response, err error) (bool, error) {
	// Do not retry on context.Canceled
	if ctx.Err() != nil {
		// If connection was closed due to client timeout retry again
		if ctx.Err() == context.DeadlineExceeded {
			return true, ctx.Err()
		}
		return false, ctx.Err()
	}

	//Retry if the request did not reach the API gateway and the error is Service Unavailable
	if err != nil {
		if v, ok := err.(*url.Error); ok {
			if strings.ToLower(v.Error()) == ServiceUnavailableError {
				return true, v
			}
		}
		return false, nil
	}

	// Check the response code. We retry on 500, 503 and 504 responses to allow
	// the server time to recover, as these are typically not permanent
	// errors and may relate to outages on the server side.
	if ok := retryableStatusCode[resp.StatusCode]; ok {
		return true, errors.Errorf("unexpected HTTP status %s", resp.Status)
	}
	return false, nil
}
