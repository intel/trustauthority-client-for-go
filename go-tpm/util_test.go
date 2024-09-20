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

// TODO [CASSINI-17044]: Current unit tests are for debugging phyical TPMs and will be
// be updated at a later date.

var testPcrSelections = map[string][]PcrSelection{
	"": []PcrSelection{},
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
