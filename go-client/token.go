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

// GetToken is used to get attestation token from Amber
func (client *amberClient) GetToken(nonce *Nonce, policyIds []uuid.UUID, evidence *Evidence) ([]byte, error) {

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
		headerAccept:      mimeApplicationJwt,
		headerContentType: mimeApplicationJson,
	}

	var attestationToken []byte
	processResponse := func(resp *http.Response) error {
		var err error
		attestationToken, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Failed to read body from %s: %s", url, err)
		}
		return nil
	}

	if err := doRequest(client.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
		return nil, err
	}

	return attestationToken, nil
}

// VerifyToken is used to do signature verification of attestation token recieved from Amber
func (client *amberClient) VerifyToken(token string) (*jwt.Token, error) {
	var tokenSignCertUrl string
	var tokenSignCert []byte
	var key crypto.PublicKey

	var parsedToken *jwt.Token
	var err error

	var headers = map[string]string{
		headerAccept: "application/x-pem-file",
	}

	parsedToken, err = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if err != nil {
			return nil, errors.Errorf("Failed to parse jwt token")
		}

		if keyIDValue, keyIDExists := token.Header["jku"]; keyIDExists {

			tokenSignCertUrl, ok := keyIDValue.(string)
			if !ok {
				return nil, errors.Errorf("jku in jwt header is not valid : %v", tokenSignCertUrl)
			}

		} else {
			return nil, fmt.Errorf("jku field missing in token. field is mandatory")
		}

		_, err = url.Parse(tokenSignCertUrl)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid URL provided to download Token Sign Cert")
		}

		newRequest := func() (*http.Request, error) {
			return http.NewRequest(http.MethodGet, tokenSignCertUrl, nil)
		}

		processResponse := func(resp *http.Response) error {
			tokenSignCert, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				return errors.Errorf("Failed to read body from %s: %s", tokenSignCertUrl, err)
			}

			block, _ := pem.Decode(tokenSignCert)

			if block == nil {
				return errors.Errorf("Unable to decode pem bytes")
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				errors.Errorf("Failed to parse certificate")
			} else {
				var ok bool
				if key, ok = cert.PublicKey.(*rsa.PublicKey); ok {
					return nil
				}
			}

			return nil
		}
		if err := doRequest(client.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
			return nil, err
		}

		return key, nil
	})

	return parsedToken, nil
}
