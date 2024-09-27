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

func TestAdapterNew(t *testing.T) {
	testData := []struct {
		testName        string
		akHandle        int
		pcrSelections   string
		ownerAuth       string
		expectedAdapter *tpmAdapter
		expectError     bool
	}{
		{
			"Test default adapter",
			DefaultAkHandle,
			"",
			"",
			&defaultAdapter,
			false,
		},
		{
			"Test zero ak-handle",
			0,
			"",
			"",
			&defaultAdapter,
			false,
		},
		{
			"Test pcr selections",
			DefaultAkHandle,
			"sha256:all",
			"",
			&defaultAdapter,
			false,
		},
		{
			"Test pcr selections error",
			DefaultAkHandle,
			"xxxx",
			"",
			nil,
			true,
		},
	}

	for _, tt := range testData {
		t.Run(tt.testName, func(t *testing.T) {
			adapter, err := NewCompositeEvidenceAdapter(tt.akHandle, tt.pcrSelections, tt.ownerAuth)
			if !tt.expectError && err != nil {
				// not expecting an error but got one
				t.Fatal(err)
			} else if tt.expectError && err == nil {
				// expecting error but didn't get one
				t.Fatalf("NewCompositeEvidenceAdapterWithOptions should have returned an error")
			} else if tt.expectError && err != nil {
				// expecting error and got one -- pass unit test
				return
			}

			if !reflect.DeepEqual(adapter, tt.expectedAdapter) {
				t.Fatalf("NewCompositeEvidenceAdapterWithOptions() returned unexpected result: expected %v, got %v", tt.expectedAdapter, adapter)
			}
		})
	}
}

func TestAdapterNewWithOptions(t *testing.T) {
	testData := []struct {
		testName        string
		options         []TpmAdapterOptions
		expectedAdapter *tpmAdapter
		expectError     bool
	}{
		{
			testName:        "Test default adapter",
			options:         []TpmAdapterOptions{},
			expectedAdapter: &defaultAdapter,
			expectError:     false,
		},
		{
			testName: "Test default adapter with zero akHandle",
			options: []TpmAdapterOptions{
				WithAkHandle(0),
			},
			expectedAdapter: &defaultAdapter,
			expectError:     false,
		},
		{
			testName: "Test adapter with device type",
			options: []TpmAdapterOptions{
				WithDeviceType(MSSIM),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       MSSIM,
				ownerAuth:        "",
				imaLogPath:       "",
				uefiEventLogPath: "",
			},
			expectError: false,
		},
		{
			testName: "Test adapter with owner auth",
			options: []TpmAdapterOptions{
				WithOwnerAuth("ownerX"),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       Linux,
				ownerAuth:        "ownerX",
				imaLogPath:       "",
				uefiEventLogPath: "",
			},
			expectError: false,
		},
		{
			testName: "Test adapter with PCR selections",
			options: []TpmAdapterOptions{
				WithPcrSelections("sha256:all"),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       Linux,
				ownerAuth:        "",
				imaLogPath:       "",
				uefiEventLogPath: "",
			},
			expectError: false,
		},
		{
			testName: "Test adapter with invalid PCR selections",
			options: []TpmAdapterOptions{
				WithPcrSelections("xxxx"),
			},
			expectedAdapter: nil,
			expectError:     true,
		},
		{
			testName: "Test adapter with empty ima logs path",
			options: []TpmAdapterOptions{
				WithImaLogs(""),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       Linux,
				ownerAuth:        "",
				imaLogPath:       DefaultImaPath,
				uefiEventLogPath: "",
			},
			expectError: false,
		},
		{
			testName: "Test adapter with default ima logs path",
			options: []TpmAdapterOptions{
				WithImaLogs(DefaultImaPath),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       Linux,
				ownerAuth:        "",
				imaLogPath:       DefaultImaPath,
				uefiEventLogPath: "",
			},
			expectError: false,
		},
		{
			testName: "Test adapter with custom ima logs path",
			options: []TpmAdapterOptions{
				WithImaLogs("/proc/cpuinfo"), // a valid path that is expected to be readable on linux
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       Linux,
				ownerAuth:        "",
				imaLogPath:       "/proc/cpuinfo",
				uefiEventLogPath: "",
			},
			expectError: false,
		},
		{
			testName: "Test adapter with invalid ima logs path should fail",
			options: []TpmAdapterOptions{
				WithImaLogs("/my/invalid/path"),
			},
			expectedAdapter: nil,
			expectError:     true,
		},
		{
			testName: "Test adapter with empty event-logs path",
			options: []TpmAdapterOptions{
				WithUefiEventLogs(""),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       Linux,
				ownerAuth:        "",
				imaLogPath:       "",
				uefiEventLogPath: DefaultUefiEventLogPath,
			},
			expectError: false,
		},
		{
			testName: "Test adapter with default event-logs path",
			options: []TpmAdapterOptions{
				WithUefiEventLogs(DefaultUefiEventLogPath),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       Linux,
				ownerAuth:        "",
				imaLogPath:       "",
				uefiEventLogPath: DefaultUefiEventLogPath,
			},
			expectError: false,
		},
		{
			testName: "Test adapter with custom event-logs path",
			options: []TpmAdapterOptions{
				WithUefiEventLogs("/proc/cpuinfo"), // a valid path that is expected to be readable on linux
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       Linux,
				ownerAuth:        "",
				imaLogPath:       "",
				uefiEventLogPath: "/proc/cpuinfo",
			},
			expectError: false,
		},
		{
			testName: "Test adapter with invalid event-logs should fail",
			options: []TpmAdapterOptions{
				WithUefiEventLogs("/my/invalid/path"),
			},
			expectedAdapter: nil,
			expectError:     true,
		},
	}

	for _, tt := range testData {
		t.Run(tt.testName, func(t *testing.T) {
			adapter, err := NewCompositeEvidenceAdapterWithOptions(tt.options...)
			if !tt.expectError && err != nil {
				// not expecting an error but got one
				t.Fatal(err)
			} else if tt.expectError && err == nil {
				// expecting error but didn't get one
				t.Fatalf("NewCompositeEvidenceAdapterWithOptions should have returned an error")
			} else if tt.expectError && err != nil {
				// expecting error and got one -- pass unit test
				return
			}

			if !reflect.DeepEqual(adapter, tt.expectedAdapter) {
				t.Fatalf("NewCompositeEvidenceAdapterWithOptions() returned unexpected result: expected %v, got %v", tt.expectedAdapter, adapter)
			}
		})
	}
}

func TestAdpaterGetEvidence(t *testing.T) {

}
