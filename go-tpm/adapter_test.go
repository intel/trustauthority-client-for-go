/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"crypto"
	"net/url"
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
				withImaLogs:      false,
				withUefiLogs:     false,
				akCertificateUri: nil,
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
				withImaLogs:      false,
				withUefiLogs:     false,
				akCertificateUri: nil,
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
				withImaLogs:      false,
				withUefiLogs:     false,
				akCertificateUri: nil,
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
			testName: "Test adapter with ima logs",
			options: []TpmAdapterOptions{
				WithImaLogs(true),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       TpmDeviceLinux,
				ownerAuth:        "",
				withImaLogs:      true,
				withUefiLogs:     false,
				akCertificateUri: nil,
			},
			expectError: false,
		},
		{
			testName: "Test adapter with event-logs",
			options: []TpmAdapterOptions{
				WithUefiEventLogs(true),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       TpmDeviceLinux,
				ownerAuth:        "",
				withImaLogs:      false,
				withUefiLogs:     true,
				akCertificateUri: nil,
			},
			expectError: false,
		},
		{
			testName: "Test adapter empty ak certificate uri",
			options: []TpmAdapterOptions{
				WithAkCertificateUri(""), // an empty path is allowed for Azure TDX runtime-data scenarios
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       TpmDeviceLinux,
				ownerAuth:        "",
				withImaLogs:      false,
				withUefiLogs:     false,
				akCertificateUri: nil,
			},
			expectError: false,
		},
		{
			testName: "Test adapter file ak certificate uri",
			options: []TpmAdapterOptions{
				WithAkCertificateUri("file:///dir/myak.pem"),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:      DefaultAkHandle,
				pcrSelections: defaultPcrSelections,
				deviceType:    TpmDeviceLinux,
				ownerAuth:     "",
				withImaLogs:   false,
				withUefiLogs:  false,
				akCertificateUri: &url.URL{
					Scheme: "file",
					Path:   "/dir/myak.pem",
				},
			},
			expectError: false,
		},
		{
			testName: "Test adapter nvram ak certificate uri",
			options: []TpmAdapterOptions{
				WithAkCertificateUri("nvram://0x81010001"),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:      DefaultAkHandle,
				pcrSelections: defaultPcrSelections,
				deviceType:    TpmDeviceLinux,
				ownerAuth:     "",
				withImaLogs:   false,
				withUefiLogs:  false,
				akCertificateUri: &url.URL{
					Scheme: "nvram",
					Host:   "0x81010001",
				},
			},
			expectError: false,
		},
		{
			testName: "Test adapter invalid ak certificate uri",
			options: []TpmAdapterOptions{
				WithAkCertificateUri("xyz://123"),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       TpmDeviceLinux,
				ownerAuth:        "",
				withImaLogs:      false,
				withUefiLogs:     false,
				akCertificateUri: nil,
			},
			expectError: true,
		},
	}

	for _, tt := range testData {
		t.Run(tt.testName, func(t *testing.T) {
			adapter, err := NewTpmAdapterFactory(NewTpmFactory()).New(tt.options...)
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

func TestAdapterGetEvidencePositive(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}

	err = provisionTestAk(tpm)
	if err != nil {
		t.Fatal(err)
	}

	tpm.Close()

	adapter, err := NewTpmAdapterFactory(NewTpmFactory()).New(
		WithDeviceType(TpmDeviceMSSIM),
		WithAkHandle(testAkHandle),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = adapter.GetEvidence(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
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
