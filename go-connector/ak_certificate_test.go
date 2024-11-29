/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package connector

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetAKCertificate(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == akProvisioningApiPath {
			w.WriteHeader(http.StatusOK)
			response := akCertificateRequestResponse{}

			j, err := json.Marshal(&response)
			if err != nil {
				t.Fatal(err)
			}

			w.Write([]byte(j))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	ctr, err := New(&Config{
		ApiUrl: testServer.URL,
		TlsCfg: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, err = ctr.GetAKCertificate(&x509.Certificate{}, make([]byte, 100))
	if err != nil {
		t.Fatal(err)
	}
}
