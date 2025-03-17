/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"bytes"
	"testing"
)

func TestString2Bytes(t *testing.T) {
	testData := []struct {
		str           string
		bytes         []byte
		errorExpected bool
	}{
		{"", nil, false},
		{"0x00000000", []byte{0, 0, 0, 0}, false},
		{"AAAAAA==", []byte{0, 0, 0, 0}, false},
		{"notbase64", nil, true},
		{"0xnothex", nil, true},
	}

	for _, td := range testData {
		results, err := string2bytes(td.str)
		if !td.errorExpected && err != nil {
			t.Fatal(err)
		} else if td.errorExpected && err == nil {
			t.Fatal("Expected error, got nil")
		}

		if bytes.Compare(results, td.bytes) != 0 {
			t.Fatalf("Expected %v, got %v", td.bytes, results)
		}
	}
}
