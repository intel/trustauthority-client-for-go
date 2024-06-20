/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// TODO:  Close on TPM Ak certificate handling and remove the need on the  "azure" part of the endpoint
const attestV2Endpoint = "appraisal/v2/attest/azure"

// AttestationToken is a JWT string recieved from Trust Authority
type AttestationToken string

// Verifier is an interface which exposes methods for attesting composite evidence
// using ITA's /appraisal/v2/attest endpoint
type Verifier interface {
	Attest(evidence interface{}) (AttestationToken, error)
}

// VerifierOption supports configuration of Verifier instances.
type VerifierOption func(*verifier) error

type verifier struct {
	ctr       *trustAuthorityConnector
	requestId uuid.UUID
}

// NewVerifier creates a Verfier with the supplied options.
func (ctr *trustAuthorityConnector) NewVerifier(options ...VerifierOption) (Verifier, error) {

	v := &verifier{
		ctr: ctr,
	}

	for _, option := range options {
		if err := option(v); err != nil {
			return nil, err
		}
	}

	if v.requestId == uuid.Nil {
		v.requestId = uuid.New()
	}

	return v, nil
}

// WithRequestId sets the request ID to help troubleshooting.
func WithRequestId(requestId uuid.UUID) VerifierOption {
	return func(v *verifier) error {
		v.requestId = requestId
		return nil
	}
}

func (v *verifier) Attest(evidence interface{}) (AttestationToken, error) {
	url := fmt.Sprintf("%s/%s", v.ctr.cfg.ApiUrl, attestV2Endpoint)

	requestBody, err := json.Marshal(evidence)
	if err != nil {
		return "", err
	}

	logrus.Debugf("REQUEST BODY: %s", string(requestBody))

	newRequest := func() (*http.Request, error) {
		return http.NewRequest(http.MethodPost, url, bytes.NewReader(requestBody))
	}

	var headers = map[string]string{
		headerXApiKey:     v.ctr.cfg.ApiKey,
		headerAccept:      mimeApplicationJson,
		headerContentType: mimeApplicationJson,
		HeaderRequestId:   v.requestId.String(),
	}

	var response GetTokenResponse
	processResponse := func(resp *http.Response) error {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Failed to read body from %s: %s", url, err)
		}

		if resp.StatusCode != http.StatusOK {
			return errors.Errorf("Request returned %d: %q", resp.StatusCode, string(body))
		}

		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		err = dec.Decode(&response)
		if err != nil {
			return errors.Errorf("Failed to decode json from %s: %s", err, string(body))
		}
		return nil
	}

	if err := doRequest(*v.ctr.rclient, v.ctr.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
		return "", err
	}

	return AttestationToken(response.Token), nil
}
