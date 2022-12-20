/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
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
			headerAccept: "application/x-pem-file",
		}

		var key crypto.PublicKey
		processResponse := func(resp *http.Response) error {
			tokenSignCert, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return errors.Errorf("Failed to read body from %s: %s", tokenSignCertUrl, err)
			}

			block, _ := pem.Decode(tokenSignCert)
			if block == nil {
				return errors.New("Unable to decode pem bytes")
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return errors.Wrap(err, "Failed to parse certificate")
			}

			var ok bool
			if key, ok = cert.PublicKey.(*rsa.PublicKey); !ok {
				return errors.New("Certificate has invalid public key")
			}

			return nil
		}

		if err := doRequest(client.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
			return nil, err
		}

		return key, nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse jwt token")
	}

	return parsedToken, nil
}
