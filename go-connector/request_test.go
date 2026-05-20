/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
)

func TestDoRequest(t *testing.T) {
	_, mux, serverURL, teardown := setup()
	defer teardown()

	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("testResponse"))
	})

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	retryableClient := retryablehttp.NewClient()
	retryableClient.HTTPClient.Transport = &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	url := fmt.Sprintf("%s/test", serverURL)
	newRequest := func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, url, nil)
	}

	var queryParams = map[string]string{
		"param": "value",
	}

	var headers = map[string]string{
		"header": "value",
	}

	processResponse := func(resp *http.Response) error {
		return nil
	}

	if err := doRequest(retryableClient, newRequest, queryParams, headers, processResponse); err != nil {
		t.Errorf("doRequest returned unexpected error: %v", err)
	}
}

func TestDoRequest_badRequest(t *testing.T) {

	newRequest := func() (*http.Request, error) {
		return nil, errors.New("Bad Request")
	}

	if err := doRequest(retryablehttp.NewClient(), newRequest, nil, nil, nil); err == nil {
		t.Error("doRequest returned nil, expected error")
	}
}

func TestDoRequest_emptyResponse(t *testing.T) {
	_, mux, serverURL, teardown := setup()
	defer teardown()

	mux.HandleFunc("/test/bad", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	retryableClient := retryablehttp.NewClient()
	retryableClient.HTTPClient.Transport = &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	url := fmt.Sprintf("%s/test/bad", serverURL)
	newRequest := func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, url, nil)
	}

	if err := doRequest(retryableClient, newRequest, nil, nil, nil); err == nil {
		t.Error("doRequest returned nil, expected error")
	}
}

func TestDoRequest_InternalServerError(t *testing.T) {
	_, mux, serverURL, teardown := setup()
	defer teardown()

	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	retryableClient := retryablehttp.NewClient()
	retryableClient.HTTPClient.Transport = &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	url := fmt.Sprintf("%s/test", serverURL)
	newRequest := func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, url, nil)
	}

	if err := doRequest(retryableClient, newRequest, nil, nil, nil); err == nil {
		t.Error("doRequest returned nil, expected error")
	}
}
