/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"net/http"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
)

type MockAdapter struct {
	mock.Mock
}

func (mock MockAdapter) CollectEvidence(nonce []byte) (*Evidence, error) {
	args := mock.Called(nonce)
	return args.Get(0).(*Evidence), args.Error(1)
}

func TestCollectToken(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/appraisal/v1/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"val":"` + nonceVal + `","iat":"` + nonceIat + `","signature":"` + nonceSig + `"}`))
	})

	adapter := MockAdapter{}
	evidence := &Evidence{}
	adapter.On("CollectEvidence", mock.Anything).Return(evidence, nil)

	mux.HandleFunc("/appraisal/v1/attest", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"token":"` + token + `"}`))
	})

	_, _, err := client.CollectToken(adapter, nil, "req1")
	if err != nil {
		t.Errorf("CollectToken returned unexpcted error: %v", err)
	}
}

func TestCollectToken_nonceFailure(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/appraisal/v1/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`invalid nonce`))
	})

	adapter := MockAdapter{}
	adapter.On("CollectEvidence", mock.Anything).Return(mock.Anything, nil)

	mux.HandleFunc("/appraisal/v1/attest", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"token":"` + token + `"}`))
	})

	_, _, err := client.CollectToken(adapter, nil, "req1")
	if err == nil {
		t.Errorf("CollectToken returned nil, expected error")
	}
}

func TestCollectToken_evidenceFailure(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/appraisal/v1/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"val":"` + nonceVal + `","iat":"` + nonceIat + `","signature":"` + nonceSig + `"}`))
	})

	adapter := MockAdapter{}
	evidence := &Evidence{}
	adapter.On("CollectEvidence", mock.Anything).Return(evidence, errors.New("failed to collect evidence"))

	mux.HandleFunc("/appraisal/v1/attest", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"token":"` + token + `"}`))
	})

	_, _, err := client.CollectToken(adapter, nil, "req1")
	if err == nil {
		t.Errorf("CollectToken returned nil, expected error")
	}
}

func TestCollectToken_tokenFailure(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/appraisal/v1/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"val":"` + nonceVal + `","iat":"` + nonceIat + `","signature":"` + nonceSig + `"}`))
	})

	adapter := MockAdapter{}
	evidence := &Evidence{}
	adapter.On("CollectEvidence", mock.Anything).Return(evidence, nil)

	mux.HandleFunc("/appraisal/v1/attest", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`invalid token`))
	})

	_, _, err := client.CollectToken(adapter, nil, "req1")
	if err == nil {
		t.Errorf("CollectToken returned nil, expected error")
	}
}
