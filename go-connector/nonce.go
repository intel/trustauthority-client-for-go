/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pkg/errors"
)

// GetNonce is used to get Intel Trust Authority signed nonce
func (connector *trustAuthorityConnector) GetNonce(args GetNonceArgs) (GetNonceResponse, error) {
	url := fmt.Sprintf("%s/appraisal/v2/nonce", connector.cfg.ApiUrl)

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

	if err := doRequest(*connector.rclient, connector.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
		return response, err
	}

	return response, nil
}
