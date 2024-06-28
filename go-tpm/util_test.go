/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"crypto"
	"reflect"
	"testing"
)

func TestSimple(t *testing.T) {
	pcrSelection := []PcrSelection{
		{
			Hash: crypto.SHA1,
			Pcrs: []int{0, 1, 2, 3, 4, 5, 6, 7},
		},
	}

	s, err := toTpm2PcrSelectionList(pcrSelection...)
	if err != nil {
		t.Fatal(err)
	}

	if len(s) != 1 {
		t.Fatal("Expected 1")
	}
}

func TestDefault(t *testing.T) {
	pcrSelection := []PcrSelection{}
	_, err := toTpm2PcrSelectionList(pcrSelection...)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(pcrSelection, defaultPcrSelections) {
		t.Errorf("Expected %+v, got %+v", defaultPcrSelections, pcrSelection)
	}
}

// TODO [CASSINI-17044]: Current unit tests are for debugging phyical TPMs and will be
// be updated at a later date.

var testPcrSelections = map[string][]tpm.PcrSelection{
	"": []tpm.PcrSelection{},
	"sha1:1,2,3": []tpm.PcrSelection{
		{
			Hash: crypto.SHA1,
			Pcrs: []int{1, 2, 3},
		},
	},
	"sha1:1,2,3+sha256:1,2,3": []tpm.PcrSelection{
		{
			Hash: crypto.SHA1,
			Pcrs: []int{1, 2, 3},
		},
		{
			Hash: crypto.SHA256,
			Pcrs: []int{1, 2, 3},
		},
	},
	"sha1:400":    nil,
	"sha43:1,2,3": nil,
}

func TestParsePcrSelections(t *testing.T) {

	for arg, expected := range testPcrSelections {
		selections, err := parsePcrSelections(arg)

		// if nil was specified in testPcrSelections, then an error
		// is expected (continue)
		if expected == nil && selections == nil && err != nil {
			continue
		}

		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(selections, expected) {
			t.Errorf("Expected %+v, got %+v", expected, selections)
		}
	}
}
