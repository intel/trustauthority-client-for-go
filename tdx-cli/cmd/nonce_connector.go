/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"crypto/x509"

	"github.com/golang-jwt/jwt/v5"
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/pkg/errors"
)

// staticNonceConnector implements connector.Connector but only supports GetNonce.
type staticNonceConnector struct {
	nonce *connector.VerifierNonce
}

func (s *staticNonceConnector) GetNonce(args connector.GetNonceArgs) (connector.GetNonceResponse, error) {
	return connector.GetNonceResponse{Nonce: s.nonce}, nil
}

func (s *staticNonceConnector) GetTokenSigningCertificates() ([]byte, error) {
	return nil, errors.New("not supported by staticNonceConnector")
}

func (s *staticNonceConnector) GetToken(args connector.GetTokenArgs) (connector.GetTokenResponse, error) {
	return connector.GetTokenResponse{}, errors.New("not supported by staticNonceConnector")
}

func (s *staticNonceConnector) Attest(args connector.AttestArgs) (connector.AttestResponse, error) {
	return connector.AttestResponse{}, errors.New("not supported by staticNonceConnector")
}

func (s *staticNonceConnector) VerifyToken(tokenString string) (*jwt.Token, error) {
	return nil, errors.New("not supported by staticNonceConnector")
}

func (s *staticNonceConnector) AttestEvidence(evidence interface{}, cloudProvider string, reqId string) (connector.AttestResponse, error) {
	return connector.AttestResponse{}, errors.New("not supported by staticNonceConnector")
}

func (s *staticNonceConnector) GetAKCertificate(ekCert *x509.Certificate, akTpmtPublic []byte) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, errors.New("not supported by staticNonceConnector")
}
