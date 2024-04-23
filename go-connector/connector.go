/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Connector is an interface which exposes methods for calling Intel Trust Authority REST APIs
type Connector interface {
	GetTokenSigningCertificates() ([]byte, error)
	GetNonce(GetNonceArgs) (GetNonceResponse, error)
	GetToken(GetTokenArgs) (GetTokenResponse, error)
	Attest(AttestArgs) (AttestResponse, error)
	VerifyToken(string) (*jwt.Token, error)

	// NewVerifier creates a new Verifier instance that facilitates
	// composite attestation with the /appraisal/v2/attest endpoint
	NewVerifier(options ...VerifierOption) (Verifier, error)
}

// EvidenceAdapter is an interface which exposes methods for collecting Quote from Platform
type EvidenceAdapter interface {
	CollectEvidence(nonce []byte) (*Evidence, error)
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

// Evidence is used to store Quote to be sent for Attestation
type Evidence struct {
	Type        uint32
	Quote       []byte
	UserData    []byte
	EventLog    []byte
	RuntimeData []byte
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
	url     *url.URL
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
		err = validateURLScheme(cfg.BaseUrl)
		if err != nil {
			return nil, errors.New("Invalid Trust Authority base URL")
		}
	}

	if cfg.ApiUrl != "" {
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

// Options for configuring a Connector
type ConnectorOption func(*Config) error

// NewFromOptions returns a new Connector instance with the provided options.
func NewFromOptions(opts ...ConnectorOption) (Connector, error) {
	cfg := &Config{
		ApiKey:  "",
		ApiUrl:  DefaultApiUrl,
		BaseUrl: DefaultBaseUrl,
		TlsCfg: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
		RetryConfig: &RetryConfig{
			CheckRetry: defaultRetryPolicy,
		},
	}

	for _, option := range opts {
		if err := option(cfg); err != nil {
			return nil, err
		}
	}

	return New(cfg)
}

// WithApiKey provides the API key for the Trust Authority
func WithApiKey(apiKey string) ConnectorOption {
	return func(cfg *Config) error {
		cfg.ApiKey = apiKey
		return nil
	}
}

// WithApiUrl option configures the connector's API URL for the Trust Authority.
// If not provided, the default value https://api.trustauthority.intel.com is used.
func WithApiUrl(apiUrl string) ConnectorOption {
	return func(cfg *Config) error {
		u, err := url.Parse(apiUrl)
		if err != nil {
			return err
		}

		cfg.ApiUrl = u.String()
		return nil
	}
}

// WithBaseUrl option configures the connector's base URL for the Trust Authority.
// If not provided, the default value https://trustauthority.intel.com is used.
func WithBaseUrl(baseUrl string) ConnectorOption {
	return func(cfg *Config) error {
		u, err := url.Parse(baseUrl)
		if err != nil {
			return err
		}

		cfg.BaseUrl = u.String()
		return nil
	}
}

// WithRetryConfig option configures the connector's TLS connection.
// If not provided, TLS 1.2 is enabled and used.
func WithTlsConfig(tlsCfg *tls.Config) ConnectorOption {
	return func(cfg *Config) error {
		if tlsCfg == nil {
			return errors.New("TLS config cannot be nil")
		}

		if tlsCfg.InsecureSkipVerify {
			logrus.Warn("TLS verification is disabled")
		}

		if tlsCfg.MinVersion < tls.VersionTLS12 {
			return errors.New("Minimum TLS version must be 1.2 or higher")
		}

		cfg.TlsCfg = tlsCfg
		return nil
	}
}

// TODO:  Retry config (ex. WithRetryMax())

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
		return errors.New("Invalid URL, scheme must be https")
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
