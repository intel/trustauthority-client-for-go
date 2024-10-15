/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"crypto"
	_ "embed"
	"reflect"
	"syscall"
	"testing"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/pkg/errors"
)

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
				WithDeviceType(TpmDeviceMSSIM),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       TpmDeviceMSSIM,
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
				deviceType:       TpmDeviceLinux,
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
				deviceType:       TpmDeviceLinux,
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
				deviceType:       TpmDeviceLinux,
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
				deviceType:       TpmDeviceLinux,
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
				deviceType:       TpmDeviceLinux,
				ownerAuth:        "",
				imaLogPath:       "/proc/cpuinfo",
				uefiEventLogPath: "",
			},
			expectError: false,
		},
		{
			testName: "Test adapter with empty event-logs path",
			options: []TpmAdapterOptions{
				WithUefiEventLogs(""),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       TpmDeviceLinux,
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
				deviceType:       TpmDeviceLinux,
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
				deviceType:       TpmDeviceLinux,
				ownerAuth:        "",
				imaLogPath:       "",
				uefiEventLogPath: "/proc/cpuinfo",
			},
			expectError: false,
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
	t.Skip() // TODO:  This test cannot be run until AK Provisioning is implemented (needed for GetQuote)
}

// Raw /sys/kernel/security/tpm0/binary_bios_measurements file from Azure TDX CVM.
//
//go:embed test_data/binary_bios_measurements
var binary_bios_measurements []byte

func TestAdpaterFilterPositive(t *testing.T) {
	filterEventLogs(binary_bios_measurements, defaultPcrSelections...)
}

func TestAdapterNonceHash(t *testing.T) {
	testData := []struct {
		testName       string
		verifierNonce  *connector.VerifierNonce
		userData       []byte
		expectedLength int
		errorExpected  bool
	}{
		{
			"Test nil nonce",
			nil,
			nil,
			0,
			false,
		},
		{
			"Test with just VerifyNonce",
			&connector.VerifierNonce{
				Iat: make([]byte, crypto.SHA256.Size()),
				Val: make([]byte, crypto.SHA256.Size()),
			},
			nil,
			crypto.SHA256.Size(),
			false,
		},
		{
			"Test with just user data",
			nil,
			make([]byte, 2),
			crypto.SHA256.Size(),
			false,
		},
	}

	for _, td := range testData {
		t.Run(td.testName, func(t *testing.T) {
			h, err := createNonceHash(td.verifierNonce, td.userData)
			if !td.errorExpected && err != nil {
				// not expecting an error but got one
				t.Fatal(err)
			} else if td.errorExpected && err == nil {
				// expecting an error but got none
				t.Fatal("Expected an error")
			} else if td.errorExpected && err != nil {
				// expecting an error and got one
				return
			}

			if len(h) != td.expectedLength {
				t.Fatalf("Expected hash length %d, got %d", td.expectedLength, len(h))
			}
		})
	}
}

func TestValidFilePaths(t *testing.T) {
	testData := []struct {
		testName      string
		filePath      string
		expectedError error
	}{
		{"Positive test case", "adapter_test.go", nil}, // this file "should" exist
		{"Symlink should fail", "/etc/os-release", ErrSymlinksNotAllowed},
		{"Path traversal should fail", "/etc/../etc/os-release", ErrPathTraversal},
		{"Invalid path should fail", "/etc/does-not-exist", syscall.Errno(syscall.ENOENT)},
	}

	for _, td := range testData {
		t.Run(td.testName, func(t *testing.T) {
			err := validateFilePath(td.filePath)
			if td.expectedError == nil && err != nil {
				// not expecting an error but got one
				t.Fatal(err)
			} else if td.expectedError != nil && err == nil {
				// expecting an error but got none
				t.Fatalf("Expected error %v", td.expectedError)
			} else {
				if !errors.Is(err, td.expectedError) {
					t.Fatalf("Expected error %v, but got %v", td.expectedError, err)
				}
			}
		})
	}
}
