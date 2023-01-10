/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
)

// tokenRequest holds all the data required for attestation
type tokenRequest struct {
	Quote     []byte      `json:"quote"`
	Nonce     *Nonce      `json:"nonce,omitempty"`
	UserData  []byte      `json:"user_data,omitempty"`
	PolicyIds []uuid.UUID `json:"policy_ids,omitempty"`
	EventLog  []byte      `json:"event_log,omitempty"`
}

type AttestationTokenResponse struct {
	Token string `json:"token"`
}

// GetToken is used to get attestation token from Amber
func (client *amberClient) GetToken(nonce *Nonce, policyIds []uuid.UUID, evidence *Evidence) (string, error) {

	url := fmt.Sprintf("%s/appraisal/v1/attest", client.cfg.Url)

	newRequest := func() (*http.Request, error) {
		tr := tokenRequest{
			Quote:     evidence.Evidence,
			Nonce:     nonce,
			UserData:  evidence.UserData,
			PolicyIds: policyIds,
			EventLog:  evidence.EventLog,
		}

		body, err := json.Marshal(tr)
		if err != nil {
			return nil, err
		}

		return http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	}

	var headers = map[string]string{
		headerXApiKey:     client.cfg.ApiKey,
		headerAccept:      mimeApplicationJson,
		headerContentType: mimeApplicationJson,
	}

	var tokenResponse AttestationTokenResponse
	processResponse := func(resp *http.Response) error {
		var err error
		attestationToken, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Failed to read body from %s: %s", url, err)
		}
		err = json.Unmarshal(attestationToken, &tokenResponse)
		if err != nil {
			return errors.Wrap(err, "Error unmarshalling Token response from appraise")
		}
		return nil
	}

	if err := doRequest(client.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
		return "", err
	}
	return tokenResponse.Token, nil
}

// VerifyToken is used to do signature verification of attestation token recieved from Amber
func (client *amberClient) VerifyToken(token string) (*jwt.Token, error) {

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {

		var kid string

		keyIDValue, keyIDExists := token.Header["kid"]
		if !keyIDExists {
			return nil, errors.New("kid field missing in token header")
		} else {
			var ok bool
			kid, ok = keyIDValue.(string)
			if !ok {
				return nil, errors.Errorf("kid field in jwt header is not valid : %v", kid)
			}
		}

		jkuValue, jkuExists := token.Header["jku"]
		if !jkuExists {
			return nil, errors.New("jku field missing in token header")
		}

		tokenSignCertUrl, ok := jkuValue.(string)
		if !ok {
			return nil, errors.Errorf("jku in jwt header is not a valid string: %v", tokenSignCertUrl)
		}

		_, err := url.Parse(tokenSignCertUrl)
		if err != nil {
			return nil, errors.Wrap(err, "malformed URL provided for Token Signing Cert download")
		}

		newRequest := func() (*http.Request, error) {
			return http.NewRequest(http.MethodGet, tokenSignCertUrl, nil)
		}

		var headers = map[string]string{
			headerAccept: "application/json",
		}

		var pubKey interface{}
		processResponse := func(resp *http.Response) error {
			// Read the JWKS payload from HTTP Response body
			jwks, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return errors.Errorf("Failed to read body from %s: %s", tokenSignCertUrl, err)
			}

			// Unmarshal the JWKS
			jwkSet, err := jwk.Parse(jwks)
			if err != nil {
				return errors.New("Unable to unmarshal response into a JWT Key Set")
			}

			jwkKey, found := jwkSet.LookupKeyID(kid)
			if !found {
				return errors.New("Could not find Key matching the key id")
			}

			// Verify the cert chain. x5c field in the JWKS would contain the cert chain
			atsCerts := jwkKey.X509CertChain()

			root := x509.NewCertPool()
			intermediate := x509.NewCertPool()
			var leafCert *x509.Certificate

			for i := 0; i < atsCerts.Len(); i++ {
				atsCert, ok := atsCerts.Get(i)
				if !ok {
					return errors.Errorf("Failed to fetch certificate at index %d", i)
				}

				cer, err := cert.Parse(atsCert)
				if err != nil {
					return errors.Errorf("Failed to parse x509 certificate[%d]: %v", i, err)
				}

				if cer.IsCA && cer.BasicConstraintsValid && strings.Contains(cer.Subject.CommonName, "Root CA") {
					root.AddCert(cer)
				} else if strings.Contains(cer.Subject.CommonName, "Signing CA") {
					intermediate.AddCert(cer)
				} else {
					leafCert = cer
				}
			}

			// Verify the Leaf certificate against the CA
			opts := x509.VerifyOptions{
				Roots:         root,
				Intermediates: intermediate,
			}

			if _, err := leafCert.Verify(opts); err != nil {
				return errors.Errorf("Failed to verify cert chain: %v", err.Error())
			}

			// Extract the public key from JWK using exponent and modulus
			err = jwkKey.Raw(&pubKey)
			if err != nil {
				return errors.New("Failed to extract Public Key from Certificate")
			}
			return nil
		}

		if err := doRequest(client.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
			return nil, err
		}

		return pubKey, nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse jwt token")
	}

	return parsedToken, nil
}
