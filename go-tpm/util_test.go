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

	"github.com/canonical/go-tpm2"
)

var testPcrSelections = map[string][]PcrSelection{
	"": defaultPcrSelections,
	"sha1:all": []PcrSelection{
		{
			Hash: crypto.SHA1,
			Pcrs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
		},
	},
	"sha1:1,2,3": []PcrSelection{
		{
			Hash: crypto.SHA1,
			Pcrs: []int{1, 2, 3},
		},
	},
	"sha1:1,2,3+sha256:1,2,3": []PcrSelection{
		{
			Hash: crypto.SHA1,
			Pcrs: []int{1, 2, 3},
		},
		{
			Hash: crypto.SHA256,
			Pcrs: []int{1, 2, 3},
		},
	},
	"sha1:all+sha256:1,2,3": []PcrSelection{
		{
			Hash: crypto.SHA1,
			Pcrs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
		},
		{
			Hash: crypto.SHA256,
			Pcrs: []int{1, 2, 3},
		},
	},
	"sha384:1,2,3": []PcrSelection{
		{
			Hash: crypto.SHA384,
			Pcrs: []int{1, 2, 3},
		},
	},
	"sha512:1,2,3": []PcrSelection{
		{
			Hash: crypto.SHA512,
			Pcrs: []int{1, 2, 3},
		},
	},
	"sha1:400":    nil, // invalid PCR number
	"sha43:1,2,3": nil, // invalid hash algorithm
	"sha1:x,2,3":  nil, // not a number string
}

func TestUtilParsePcrSelections(t *testing.T) {

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

func TestUtilToTpm2SelectionList(t *testing.T) {
	testData := []struct {
		testName      string
		selections    []PcrSelection
		expected      tpm2.PCRSelectionList
		errorExpected bool
	}{
		{
			"Test default selection list",
			[]PcrSelection{},
			tpm2.PCRSelectionList{
				{
					Hash:   tpm2.HashAlgorithmSHA256,
					Select: tpm2.PCRSelect{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
				},
			},
			false,
		},
		{
			"Test SHA1",
			[]PcrSelection{
				{
					Hash: crypto.SHA1,
					Pcrs: []int{0, 1, 2, 3},
				},
			},
			tpm2.PCRSelectionList{
				{
					Hash:   tpm2.HashAlgorithmSHA1,
					Select: tpm2.PCRSelect{0, 1, 2, 3},
				},
			},
			false,
		},
		{
			"Test SHA384",
			[]PcrSelection{
				{
					Hash: crypto.SHA384,
					Pcrs: []int{0, 1, 2, 3},
				},
			},
			tpm2.PCRSelectionList{
				{
					Hash:   tpm2.HashAlgorithmSHA384,
					Select: tpm2.PCRSelect{0, 1, 2, 3},
				},
			},
			false,
		},
		{
			"Test SHA512",
			[]PcrSelection{
				{
					Hash: crypto.SHA512,
					Pcrs: []int{0, 1, 2, 3},
				},
			},
			tpm2.PCRSelectionList{
				{
					Hash:   tpm2.HashAlgorithmSHA512,
					Select: tpm2.PCRSelect{0, 1, 2, 3},
				},
			},
			false,
		},
		{
			"Unsupported Algorithm",
			[]PcrSelection{
				{
					Hash: crypto.MD5SHA1,
					Pcrs: []int{0, 1, 2, 3},
				},
			},
			tpm2.PCRSelectionList{
				{
					Hash:   tpm2.HashAlgorithmSHA512,
					Select: tpm2.PCRSelect{0, 1, 2, 3},
				},
			},
			true,
		},
	}

	for _, tt := range testData {
		t.Run(tt.testName, func(t *testing.T) {
			selectionList, err := toTpm2PcrSelectionList(tt.selections...)
			if !tt.errorExpected && err != nil {
				t.Fatalf("Unexpected error: %v", err)
			} else if tt.errorExpected && err == nil {
				t.Fatalf("Expected error but got none")
			} else if tt.errorExpected && err != nil {
				return // ok, exected an error
			}

			if !reflect.DeepEqual(selectionList, tt.expected) {
				t.Fatalf("Expected %+v, got %+v", tt.expected, selectionList)
			}
		})
	}
}
