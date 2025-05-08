/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"io"
	"net/http"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
)

// doRequest creates an API request, sends the API request and returns the API response
func doRequest(rclient *retryablehttp.Client,
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

	var resp *http.Response
	if resp, err = rclient.StandardClient().Do(req); err != nil {
		return errors.Errorf("Request to %q failed: %s", req.URL, err)
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
		traceId, requestId := resp.Header.Get(HeaderTraceId), resp.Header.Get(HeaderRequestId)
		response, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Failed to read response body: %s, Trace-Id = %s, Request-Id = %s", err, traceId, requestId)
		}
		return errors.Errorf("Request to %q failed: StatusCode = %d, Response = %s, Trace-Id = %s, Request-Id = %s", req.URL, resp.StatusCode, string(response), traceId, requestId)
	}

	return processResponse(resp)
}
