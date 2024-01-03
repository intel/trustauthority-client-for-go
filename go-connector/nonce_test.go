/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"encoding/base64"
	"net/http"
	"reflect"
	"testing"
)

var (
	nonceVal = "g9QC7VxV0n8dID0zSJeVLSULqYCJuv4iMepby91xukrhXgKrKscGXB5lxmT2s3POjxVOG+fSPCYpOKYWRRWAyQ=="
	nonceIat = "MjAyMi0wOC0yNCAxMjozNjozMi45Mjk3MjIwNzUgKzAwMDAgVVRD"
	nonceSig = "WswVG3rOPJIuVmMNG2GZ6IF4hD+QfuJ/PigIRaHtQitGAHRCRzgtW8+8UbXe9vJfjnapjw7RQyzpT+vPGVpxRSoiBaj54RsedI38K9ubFd3gPvsMlYltgFRSAtb1ViWZxMhL0yA9+xzgv0D+11mpNEz8nt3HK4oALV5EAxqJYCmKZRzi3/LJe842AY8DVcV9eUZQ8RBx7gNe72Ex1fU3+qF9A9MuOgKqJ41/7HFTY0rCpcBS8k6E1VBSatk4XTj5KNcluI3LoAOvBuiwObgmNKT8Nyc4JAEc+gmf9e9taIgt7QNFEtl3nwPQuiCLIh0FHdXPYumiQ0mclU8nfQL8ZUoe/GqgOd58+fZoHeGvFoeyjQ7Q0Ini1rWEzwOY5gik9yH57/JTEJTI8Evc0L8ggRO4M/sZ2ZTyIq5yRUISB2eDh6qTfbKgSr5LpxW8IRl0y9fp8CEuzhFxKcOeld9p61yb040P+QhemhP/O1E5tf4y4Pz/ISASiKUBFSTh4yYx"
)

func TestGetNonce(t *testing.T) {
	connector, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc(nonceEndpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"val":"` + nonceVal + `","iat":"` + nonceIat + `","signature":"` + nonceSig + `"}`))
	})

	got, err := connector.GetNonce(GetNonceArgs{"req1"})
	if err != nil {
		t.Errorf("GetNonce returned unexpected error: %v", err)
		return
	}

	val, _ := base64.StdEncoding.DecodeString(nonceVal)
	iat, _ := base64.StdEncoding.DecodeString(nonceIat)
	sig, _ := base64.StdEncoding.DecodeString(nonceSig)

	want := &VerifierNonce{
		Val:       val,
		Iat:       iat,
		Signature: sig,
	}
	if !reflect.DeepEqual(got.Nonce, want) {
		t.Errorf("GetNonce returned: %v, want %v", got, want)
	}
}

func TestGetNonce_invalidNonce(t *testing.T) {
	connector, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc(nonceEndpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`invalid nonce`))
	})

	_, err := connector.GetNonce(GetNonceArgs{"req1"})
	if err == nil {
		t.Error("GetNonce returned nil, expected error")
	}
}
