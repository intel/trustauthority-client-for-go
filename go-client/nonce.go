/*
 *   Copyright (c) 2022 Intel Corporation
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
func (client *amberClient) GetNonce(reqId string) (*VerifierNonce, map[string][]string, error) {
	url := fmt.Sprintf("%s/appraisal/v1/nonce", client.cfg.ApiUrl)

	newRequest := func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, url, nil)
	}

	var headers = map[string]string{
		headerXApiKey:   client.cfg.ApiKey,
		headerAccept:    mimeApplicationJson,
		HeaderRequestId: reqId,
	}

	var nonce VerifierNonce
	var respHeaders map[string][]string
	processResponse := func(resp *http.Response) error {
		respHeaders = resp.Header
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Failed to read body from %s: %s", url, err)
		}

		if err = json.Unmarshal(body, &nonce); err != nil {
			return errors.Errorf("Failed to decode json from %s: %s", url, err)
		}

		return nil
	}

	if err := doRequest(client.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
		return nil, respHeaders, err
	}

	return &nonce, respHeaders, nil
}
