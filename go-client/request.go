/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"crypto/tls"
	"io"
	"net/http"

	"github.com/pkg/errors"
)

// doRequest creates an API request, sends the API request and returns the API response
func doRequest(tlsCfg *tls.Config,
	newRequest func() (*http.Request, error),
	queryParams map[string]string,
	headers map[string]string,
	processResponse func(*http.Response) error) error {

	var req *http.Request
	var err error

	if req, err = newRequest(); err != nil {
		return err
	}

	if queryParams != nil {
		q := req.URL.Query()
		for param, val := range queryParams {
			q.Add(param, val)
		}
		req.URL.RawQuery = q.Encode()
	}

	for name, val := range headers {
		req.Header.Add(name, val)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			Proxy:           http.ProxyFromEnvironment,
		},
	}

	var resp *http.Response
	if resp, err = client.Do(req); err != nil {
		return errors.Wrapf(err, "Request to %q failed", req.URL)
	}

	if resp != nil {
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				errors.Errorf("Failed to close response body")
			}
		}()
	}

	if resp.StatusCode != http.StatusOK || resp.ContentLength == 0 {
		response, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Failed to read response body: %s", err)
		}
		return errors.Errorf("Request to %q failed: StatusCode = %d, Response = %s", req.URL, resp.StatusCode, string(response))
	}

	return processResponse(resp)
}
