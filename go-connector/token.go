/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
)

// tokenRequest holds all the data required for attestation
type tokenRequest struct {
	Quote           []byte         `json:"quote"`
	VerifierNonce   *VerifierNonce `json:"verifier_nonce,omitempty"`
	RuntimeData     []byte         `json:"runtime_data,omitempty"`
	PolicyIds       []uuid.UUID    `json:"policy_ids,omitempty"`
	EventLog        []byte         `json:"event_log,omitempty"`
	TokenSigningAlg string         `json:"token_signing_alg,omitempty"`
	PolicyMustMatch bool           `json:"policy_must_match",omitempty"`
}

// AttestationTokenResponse holds the token recieved from Intel Trust Authority
type AttestationTokenResponse struct {
	Token string `json:"token"`
}

// GetToken is used to get attestation token from Intel Trust Authority
func (connector *trustAuthorityConnector) GetToken(args GetTokenArgs) (GetTokenResponse, error) {
	url := fmt.Sprintf("%s/appraisal/v1/attest", connector.cfg.ApiUrl)

	newRequest := func() (*http.Request, error) {
		tr := tokenRequest{
			Quote:           args.Evidence.Evidence,
			VerifierNonce:   args.Nonce,
			RuntimeData:     args.Evidence.UserData,
			PolicyIds:       args.PolicyIds,
			EventLog:        args.Evidence.EventLog,
			TokenSigningAlg: args.TokenSigningAlg,
			PolicyMustMatch: args.PolicyMustMatch,
		}

		body, err := json.Marshal(tr)
		if err != nil {
			return nil, err
		}

		return http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	}

	var headers = map[string]string{
		headerXApiKey:     connector.cfg.ApiKey,
		headerAccept:      mimeApplicationJson,
		headerContentType: mimeApplicationJson,
		HeaderRequestId:   args.RequestId,
	}

	var response GetTokenResponse
	processResponse := func(resp *http.Response) error {
		response.Headers = resp.Header
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Failed to read body from %s: %s", url, err)
		}

		var tokenResponse AttestationTokenResponse
		err = json.Unmarshal(body, &tokenResponse)
		if err != nil {
			return errors.Errorf("Error unmarshalling Token response from appraise: %s", err)
		}
		response.Token = tokenResponse.Token
		return nil
	}

	if err := doRequest(*connector.rclient, connector.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
		return response, err
	}

	return response, nil
}

// getCRL is used to get CRL Object from CRL distribution points
func getCRL(rclient retryablehttp.Client, crlArr []string) (*x509.RevocationList, error) {

	if len(crlArr) < 1 {
		return nil, errors.New("Invalid CDP count present in the certificate")
	}

	_, err := url.Parse(crlArr[0])
	if err != nil {
		return nil, errors.Wrap(err, "Invalid CRL distribution point")
	}

	newRequest := func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, crlArr[0], nil)
	}

	var crlObj *x509.RevocationList
	processResponse := func(resp *http.Response) error {
		crlBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrapf(err, "Failed to read body from %s", crlArr[0])
		}

		crlObj, err = x509.ParseRevocationList([]byte(crlBytes))
		if err != nil {
			return errors.Wrap(err, "Failed to parse revocation list")
		}
		return nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}
	if err := doRequest(rclient, tlsConfig, newRequest, nil, nil, processResponse); err != nil {
		return nil, err
	}
	return crlObj, nil
}

// verifyCRL is used to verify the Certificate against CRL
func verifyCRL(crl *x509.RevocationList, leafCert *x509.Certificate, caCert *x509.Certificate) error {
	if leafCert == nil || caCert == nil || crl == nil {
		return errors.New("Leaf Cert or CA Cert or CRL is nil")
	}

	//Checking CRL signed by CA Certificate
	err := crl.CheckSignatureFrom(caCert)
	if err != nil {
		return errors.Wrap(err, "CRL signature verification failed")
	}

	if crl.NextUpdate.Before(time.Now()) {
		return errors.New("Outdated CRL")
	}

	for _, rCert := range crl.RevokedCertificates {
		if rCert.SerialNumber.Cmp(leafCert.SerialNumber) == 0 {
			return errors.New("Certificate was Revoked")
		}
	}
	return nil
}

// VerifyToken is used to do signature verification of attestation token recieved from Intel Trust Authority
func (connector *trustAuthorityConnector) VerifyToken(token string) (*jwt.Token, error) {

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {

		var kid string
		keyIDValue, keyIDExists := token.Header["kid"]
		if !keyIDExists {
			return nil, errors.New("kid field missing in token header")
		} else {
			var ok bool
			kid, ok = keyIDValue.(string)
			if !ok {
				return nil, errors.Errorf("kid field in jwt header is not a valid string: %v", kid)
			}
		}

		algValue, algExists := token.Header["alg"]
		if !algExists {
			return nil, errors.New("alg field missing in token header")
		} else {
			alg, ok := algValue.(string)
			if !ok {
				return nil, errors.Errorf("alg field in jwt header is not a valid string: %v", alg)
			}
			if !ValidateTokenSigningAlg(alg) {
				return nil, fmt.Errorf("unsupported token signing algorithm, has to be RS256 or PS384")
			}
		}

		// Get the JWT Signing Certificates from Intel Trust Authority
		jwks, err := connector.GetTokenSigningCertificates()
		if err != nil {
			return nil, errors.Errorf("Failed to get token signing certificates: %s", err)
		}

		// Unmarshal the JWKS
		jwkSet, err := jwk.Parse(jwks)
		if err != nil {
			return nil, errors.Errorf("Unable to unmarshal response into a JWT Key Set: %s", err)
		}

		jwkKey, found := jwkSet.LookupKeyID(kid)
		if !found {
			return nil, errors.New("Could not find Key matching the key id")
		}

		// Verify the cert chain. x5c field in the JWKS would contain the cert chain
		atsCerts := jwkKey.X509CertChain()
		if atsCerts.Len() > AtsCertChainMaxLen {
			return nil, errors.Errorf("Token Signing Cert chain has more than %d certificates", AtsCertChainMaxLen)
		}

		root := x509.NewCertPool()
		intermediate := x509.NewCertPool()
		var leafCert *x509.Certificate
		var interCACert *x509.Certificate
		var rootCert *x509.Certificate

		for i := 0; i < atsCerts.Len(); i++ {
			atsCert, ok := atsCerts.Get(i)
			if !ok {
				return nil, errors.Errorf("Failed to fetch certificate at index %d", i)
			}

			cer, err := cert.Parse(atsCert)
			if err != nil {
				return nil, errors.Errorf("Failed to parse x509 certificate[%d]: %v", i, err)
			}

			if cer.IsCA && cer.BasicConstraintsValid && strings.Contains(cer.Subject.CommonName, "Root CA") {
				root.AddCert(cer)
				rootCert = cer
			} else if strings.Contains(cer.Subject.CommonName, "Signing CA") {
				intermediate.AddCert(cer)
				interCACert = cer
			} else {
				leafCert = cer
			}
		}

		rootCrl, err := getCRL(*connector.rclient, interCACert.CRLDistributionPoints)
		if err != nil {
			return nil, errors.Errorf("Failed to get ROOT CA CRL Object: %v", err.Error())
		}

		if err = verifyCRL(rootCrl, interCACert, rootCert); err != nil {
			return nil, errors.Errorf("Failed to check ATS CA Certificate against Root CA CRL: %v", err.Error())
		}

		atsCrl, err := getCRL(*connector.rclient, leafCert.CRLDistributionPoints)
		if err != nil {
			return nil, errors.Errorf("Failed to get ATS CRL Object: %v", err.Error())
		}

		if err = verifyCRL(atsCrl, leafCert, interCACert); err != nil {
			return nil, errors.Errorf("Failed to check ATS Leaf certificate against ATS CRL: %v", err.Error())
		}

		// Verify the Leaf certificate against the CA
		opts := x509.VerifyOptions{
			Roots:         root,
			Intermediates: intermediate,
		}

		if _, err := leafCert.Verify(opts); err != nil {
			return nil, errors.Errorf("Failed to verify cert chain: %v", err)
		}

		// Extract the public key from JWK using exponent and modulus
		var pubKey interface{}
		err = jwkKey.Raw(&pubKey)
		if err != nil {
			return nil, errors.Errorf("Failed to extract Public Key from Certificate: %s", err)
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, errors.Errorf("Failed to verify jwt token: %s", err)
	}

	return parsedToken, nil
}
