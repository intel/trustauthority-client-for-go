/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
)

// Connector is an interface which exposes methods for calling Intel Trust Authority REST APIs
type Connector interface {
	GetTokenSigningCertificates() ([]byte, error)
	GetNonce(GetNonceArgs) (GetNonceResponse, error)
	GetToken(GetTokenArgs) (GetTokenResponse, error)
	Attest(AttestArgs) (AttestResponse, error)
	VerifyToken(string) (*jwt.Token, error)

	// AttestEvidence serializes 'evidence' to json and sends it to the Trust Authority
	// for attestation.  'cloudProvider' is an optional string that is appended to the
	// attestation endpoint (ex. "azure" is routed to /v2/attest/azure).  Currently,
	// only "azure" is supported.  'reqId' is an optional string that is included in the
	// x-request-id header that can be used for troubleshooting.
	AttestEvidence(evidence interface{}, cloudProvider string, reqId string) (AttestResponse, error)

	// GetAkCertificate sends the TPM's EK certificate and the AK's TPMT_PUBLIC structure
	// to Intel Trust Authority and returns an encrypted AK certificate, a secret, and credential blob
	// that can be decrypted by the TPM (ActivateCredential command).
	GetAKCertificate(ekCert *x509.Certificate, akTpmtPublic []byte) ([]byte, []byte, []byte, error)
}

// GetNonceArgs holds the request parameters needed for getting nonce from Intel Trust Authority
type GetNonceArgs struct {
	RequestId string
}

// GetNonceResponse holds the response parameters recieved from nonce endpoint
type GetNonceResponse struct {
	Nonce   *VerifierNonce
	Headers http.Header
}

// GetTokenArgs holds the request parameters needed for getting token from Intel Trust Authority
type GetTokenArgs struct {
	Nonce           *VerifierNonce
	Evidence        *Evidence
	PolicyIds       []uuid.UUID
	RequestId       string
	attestEndpoint  string
	TokenSigningAlg string
	PolicyMustMatch bool
}

// GetTokenResponse holds the response parameters recieved from attest endpoint
type GetTokenResponse struct {
	Token   string
	Headers http.Header
}

// AttestArgs holds the request parameters needed for attestation with Intel Trust Authority
type AttestArgs struct {
	Adapter         EvidenceAdapter
	PolicyIds       []uuid.UUID
	RequestId       string
	TokenSigningAlg string
	PolicyMustMatch bool
}

// AttestResponse holds the response parameters recieved during attestation flow
type AttestResponse struct {
	Token   string
	Headers http.Header
}

// RetryConfig holds the configuration for automatic retries to tolerate minor outages
type RetryConfig struct {
	RetryWaitMin *time.Duration // Minimum time to wait between retries
	RetryWaitMax *time.Duration // Maximum time to wait between retries
	RetryMax     *int           // Maximum number of retries

	CheckRetry retryablehttp.CheckRetry
	BackOff    retryablehttp.Backoff
}

// Config holds the Intel Trust Authority configuration for Connector
type Config struct {
	BaseUrl string
	TlsCfg  *tls.Config
	ApiUrl  string
	ApiKey  string
	*RetryConfig
}

// VerifierNonce holds the signed nonce issued from Intel Trust Authority
type VerifierNonce struct {
	Val       []byte `json:"val"`
	Iat       []byte `json:"iat"`
	Signature []byte `json:"signature"`
}

// New returns a new Connector instance
func New(cfg *Config) (Connector, error) {
	var err error
	if cfg.BaseUrl != "" {
		cfg.BaseUrl = strings.TrimSuffix(cfg.BaseUrl, "/")
		err = validateURLScheme(cfg.BaseUrl)
		if err != nil {
			return nil, errors.New("Invalid Trust Authority base URL")
		}
	}

	if cfg.ApiUrl != "" {
		cfg.ApiUrl = strings.TrimSuffix(cfg.ApiUrl, "/")
		err = validateURLScheme(cfg.ApiUrl)
		if err != nil {
			return nil, errors.New("Invalid Trust Authority API URL")
		}
	}

	retryableClient := retryablehttp.NewClient()
	retryableClient.CheckRetry = defaultRetryPolicy
	retryableClient.RetryWaitMax = DefaultRetryWaitMaxSeconds * time.Second
	retryableClient.RetryWaitMin = DefaultRetryWaitMinSeconds * time.Second
	retryableClient.RetryMax = MaxRetries
	if cfg.RetryConfig == nil {
		return &trustAuthorityConnector{
			cfg:     cfg,
			rclient: retryableClient,
		}, nil
	}

	if cfg.RetryConfig.CheckRetry != nil {
		retryableClient.CheckRetry = cfg.RetryConfig.CheckRetry
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

	return &trustAuthorityConnector{
		cfg:     cfg,
		rclient: retryableClient,
	}, nil
}

// trustAuthorityConnector manages communication with Intel Trust Authority
type trustAuthorityConnector struct {
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

func validateURLScheme(inputUrl string) error {
	parsedUrl, err := url.Parse(inputUrl)
	if err != nil {
		return err
	}
	if parsedUrl.Scheme != HttpsScheme {
		return errors.New("url scheme must be https")
	}
	return nil
}

func ValidateTokenSigningAlg(input string) bool {
	validJwtTokenSignAlgs := []JwtAlg{RS256, PS384}
	for _, alg := range validJwtTokenSignAlgs {
		if strings.Compare(input, string(alg)) == 0 {
			return true
		}
	}
	return false
}
