/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"net/http"
	"testing"
)

func TestAttestEvidence(t *testing.T) {

	connector, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc(attestEndpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"token":"` + token + `"}`))
	})

	response, err := connector.AttestEvidence(&struct{}{}, "", "")
	if err != nil {
		t.Errorf("GetToken returned unexpected error: %v", err)
	}

	t.Logf("Response: %v", response)
}
