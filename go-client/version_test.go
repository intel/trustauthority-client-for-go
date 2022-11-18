/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"net/http"
	"reflect"
	"testing"
)

func TestGetAmberVersion(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/appraisal/v1/version", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"Amber","version":"1.0.0","commit":"abcdef","buildDate":""}`))
	})

	got, err := client.GetAmberVersion()
	if err != nil {
		t.Errorf("GetAmberVersion returned unexpected error: %v", err)
		return
	}

	want := &Version{
		Name:      "Amber",
		SemVer:    "1.0.0",
		Commit:    "abcdef",
		BuildDate: "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetAmberVersion returned: %v, want %v", got, want)
	}
}

func TestGetAmberVersion_invalidVersion(t *testing.T) {
	client, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc("/appraisal/v1/version", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`invalid version`))
	})

	_, err := client.GetAmberVersion()
	if err == nil {
		t.Error("GetAmberVersion returned nil, expected error")
	}
}
