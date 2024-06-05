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
