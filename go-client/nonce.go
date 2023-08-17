/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pkg/errors"
)

// GetNonce is used to get Amber signed nonce
func (client *amberClient) GetNonce(args GetNonceArgs) (GetNonceResponse, error) {
	url := fmt.Sprintf("%s/appraisal/v1/nonce", client.cfg.ApiUrl)

	newRequest := func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, url, nil)
	}

	var headers = map[string]string{
		headerXApiKey:   client.cfg.ApiKey,
		headerAccept:    mimeApplicationJson,
		HeaderRequestId: args.RequestId,
	}

	var response GetNonceResponse
	processResponse := func(resp *http.Response) error {
		response.Headers = resp.Header
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Failed to read body from %s: %s", url, err)
		}

		var nonce VerifierNonce
		if err = json.Unmarshal(body, &nonce); err != nil {
			return errors.Errorf("Failed to decode json from %s: %s", url, err)
		}
		response.Nonce = &nonce
		return nil
	}

	if err := doRequest(*client.rclient, client.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
		return response, err
	}

	return response, nil
}
