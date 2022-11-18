/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// setup sets up a test HTTP server along with a AmberClient that is
// configured to talk to that test server. Tests should register handlers on
// mux which provide mock responses for the API method being tested.
func setup() (client AmberClient, mux *http.ServeMux, serverURL string, teardown func()) {
	// mux is the HTTP request multiplexer used with the test server.
	mux = http.NewServeMux()

	// We want to ensure that tests catch mistakes where the endpoint URL is
	// specified as absolute rather than relative. It only makes a difference
	// when there's a non-empty base URL path. So, use that. See issue #752.
	//apiHandler := http.NewServeMux()
	//apiHandler.Handle(baseURLPath+"/", http.StripPrefix(baseURLPath, mux))

	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(mux)

	// client is the Amber client being tested and is
	// configured to use test server.
	cfg := Config{
		TlsCfg: &tls.Config{
			InsecureSkipVerify: true,
		},
		Url: server.URL,
	}
	client, _ = New(&cfg)

	return client, mux, server.URL, server.Close
}

func TestNew(t *testing.T) {
	cfg := Config{
		Url: "https://custom-url/api/v1",
	}

	_, err := New(&cfg)
	if err != nil {
		t.Errorf("New returned unexpected error: %v", err)
	}
}

func TestNew_badBaseURL(t *testing.T) {
	cfg := Config{
		Url: "bogus\nbase\nURL",
	}

	if _, err := New(&cfg); err == nil {
		t.Error("New retruned nil, expected error")
	}
}
