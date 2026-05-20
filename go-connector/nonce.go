/*
 *   Copyright (c) 2022-2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/pkg/errors"
)

const nonceMaxBodyBytes int64 = 4096
const nonceMaxDrainBytes = 1 << 20 // maximum bytes to drain from an oversized response body

// GetNonce is used to get Intel Trust Authority signed nonce
func (connector *trustAuthorityConnector) GetNonce(args GetNonceArgs) (GetNonceResponse, error) {
	url := connector.cfg.ApiUrl + nonceEndpoint

	newRequest := func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, url, nil)
	}

	var headers = map[string]string{
		headerXApiKey:   connector.cfg.ApiKey,
		headerAccept:    mimeApplicationJson,
		HeaderRequestId: args.RequestId,
	}

	var response GetNonceResponse
	processResponse := func(resp *http.Response) error {
		response.Headers = resp.Header
		limitReader := io.LimitReader(resp.Body, nonceMaxBodyBytes+1)
		body, err := io.ReadAll(limitReader)
		if err != nil {
			return errors.Errorf("Failed to read body from %s: %v", url, err)
		}
		if int64(len(body)) > nonceMaxBodyBytes {
			// Drain and discard remaining response body (up to a cap) so the connection can be reused.
			_, _ = io.CopyN(io.Discard, resp.Body, nonceMaxDrainBytes)
			return errors.Errorf("Failed to read body from %s: response too large", url)
		}

		var nonce VerifierNonce
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&nonce); err != nil {
			return errors.Errorf("Failed to decode json from %s: %v", url, err)
		}
		response.Nonce = &nonce
		return nil
	}

	if err := doRequest(connector.rclient, newRequest, nil, headers, processResponse); err != nil {
		return response, err
	}

	return response, nil
}
