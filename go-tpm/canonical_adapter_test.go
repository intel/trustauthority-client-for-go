/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"reflect"
	"testing"
)

func TestAdapterOptions(t *testing.T) {
	testData := []struct {
		testName        string
		options         []TpmAdapterOptions
		expectedAdapter *tpmCompositeAdapter
		expectError     bool
	}{
		{
			testName:        "Test default adapter without options",
			options:         []TpmAdapterOptions{},
			expectedAdapter: &defaultAdapter,
			expectError:     false,
		},
		{
			testName: "Test default adapter zero akHandle",
			options: []TpmAdapterOptions{
				WithAkHandle(0),
			},
			expectedAdapter: &defaultAdapter,
			expectError:     false,
		},
	}

	for _, tt := range testData {
		t.Run(tt.testName, func(t *testing.T) {
			adapter, err := NewEvidenceAdapterWithOptions(tt.options...)
			if !tt.expectError && err != nil {
				t.Fatal(err)
			} else if tt.expectError && err == nil {
				t.Fatalf("NewEvidenceAdapterWithOptions should have returned an error")
			}

			if !reflect.DeepEqual(adapter, tt.expectedAdapter) {
				t.Fatalf("NewEvidenceAdapterWithOptions() returned unexpected result: expected %v, got %v", tt.expectedAdapter, adapter)
			}
		})
	}
}
