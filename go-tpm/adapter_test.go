/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"bytes"
	"crypto"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"syscall"
	"testing"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
				withImaLogs:      "",
				withUefiLogs:     "",
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
				withImaLogs:      "",
				withUefiLogs:     "",
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
				withImaLogs:      "",
				withUefiLogs:     "",
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
				withImaLogs:      DefaultImaPath,
				withUefiLogs:     "",
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
				withImaLogs:      "",
				withUefiLogs:     DefaultUefiEventLogPath,
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
				withImaLogs:      "",
				withUefiLogs:     "",
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
				withImaLogs:   "",
				withUefiLogs:  "",
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
				withImaLogs:   "",
				withUefiLogs:  "",
				akCertificateUri: &url.URL{
					Scheme: "nvram",
					Host:   "0x81010001",
				},
			},
			expectError: false,
		},
		{
			testName: "Test adapter ak certificate uri invalid host type",
			options: []TpmAdapterOptions{
				WithAkCertificateUri("http://httpisnotsupported.com"),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       TpmDeviceLinux,
				ownerAuth:        "",
				withImaLogs:      "",
				withUefiLogs:     "",
				akCertificateUri: nil,
			},
			expectError: true,
		},
		{
			testName: "Test adapter force ak uri parse error",
			options: []TpmAdapterOptions{
				WithAkCertificateUri("\x07----"),
			},
			expectedAdapter: &tpmAdapter{
				akHandle:         DefaultAkHandle,
				pcrSelections:    defaultPcrSelections,
				deviceType:       TpmDeviceLinux,
				ownerAuth:        "",
				withImaLogs:      "",
				withUefiLogs:     "",
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

			adapter.(*tpmAdapter).tpmFactory = nil // clear the adapter so DeepEqual works
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

func TestReadAkCertificatePositive(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	// use the test ek cert for unit testing
	certBytes, err := tpm.NVRead(DefaultEkNvIndex)
	if err != nil {
		t.Fatal(err)
	}

	nvIdx := DefaultEkNvIndex + 1
	tpm.NVDefine(nvIdx, len(certBytes))
	if err != nil {
		t.Fatal(err)
	}

	err = tpm.NVWrite(nvIdx, certBytes)
	if err != nil {
		t.Fatal(err)
	}

	uri, err := url.Parse(fmt.Sprintf("nvram://%x", nvIdx))
	if err != nil {
		t.Fatal(err)
	}

	_, err = readAkCertificate(uri, tpm)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMockGetEvidenceTpmFactoryFailure(t *testing.T) {
	mockTpmFactory := MockTpmFactory{}
	mockTpmFactory.On("New", mock.Anything, mock.Anything).Return(&MockTpm{}, errors.New("unit test failure"))

	adapterFactory := NewTpmAdapterFactory(&mockTpmFactory)
	adapter, err := adapterFactory.New()
	if err != nil {
		t.Fatal(err)
	}

	_, err = adapter.GetEvidence(nil, nil)
	if !errors.Is(err, ErrTpmOpenFailure) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestMockGetEvidenceGetQuoteFailure(t *testing.T) {
	mockTpm := MockTpm{}
	mockTpm.On("GetQuote", mock.Anything, mock.Anything, mock.Anything).Return([]byte{}, []byte{}, errors.New("unit test failure"))

	mockTpmFactory := MockTpmFactory{}
	mockTpmFactory.On("New", mock.Anything, mock.Anything).Return(&mockTpm, nil)

	adapterFactory := NewTpmAdapterFactory(&mockTpmFactory)
	adapter, err := adapterFactory.New()
	if err != nil {
		t.Fatal(err)
	}

	_, err = adapter.GetEvidence(nil, nil)
	if !errors.Is(err, ErrQuoteFailure) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestMockGetEvidenceGetPcrsFailure(t *testing.T) {
	mockTpm := MockTpm{}
	mockTpm.On("GetQuote", mock.Anything, mock.Anything, mock.Anything).Return([]byte{}, []byte{}, nil)
	mockTpm.On("GetPcrs", mock.Anything).Return([]byte{}, errors.New("unit test failure"))

	mockTpmFactory := MockTpmFactory{}
	mockTpmFactory.On("New", mock.Anything, mock.Anything).Return(&mockTpm, nil)

	adapterFactory := NewTpmAdapterFactory(&mockTpmFactory)
	adapter, err := adapterFactory.New()
	if err != nil {
		t.Fatal(err)
	}

	_, err = adapter.GetEvidence(nil, nil)
	if !errors.Is(err, ErrPCRsFailure) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestMockGetEvidenceImaLogFailure(t *testing.T) {
	mockTpm := MockTpm{}
	mockTpm.On("GetQuote", mock.Anything, mock.Anything, mock.Anything).Return([]byte{}, []byte{}, nil)
	mockTpm.On("GetPcrs", mock.Anything).Return([]byte{}, nil)

	mockTpmFactory := MockTpmFactory{}
	mockTpmFactory.On("New", mock.Anything, mock.Anything).Return(&mockTpm, nil)

	adapterFactory := NewTpmAdapterFactory(&mockTpmFactory)
	adapter, err := adapterFactory.New()
	if err != nil {
		t.Fatal(err)
	}
	adapter.(*tpmAdapter).withImaLogs = "/some/invalid/path"

	_, err = adapter.GetEvidence(nil, nil)
	if !errors.Is(err, ErrFailedToReadIMALogs) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestMockGetEvidenceUefiLogFailure(t *testing.T) {
	mockTpm := MockTpm{}
	mockTpm.On("GetQuote", mock.Anything, mock.Anything, mock.Anything).Return([]byte{}, []byte{}, nil)
	mockTpm.On("GetPcrs", mock.Anything).Return([]byte{}, nil)

	mockTpmFactory := MockTpmFactory{}
	mockTpmFactory.On("New", mock.Anything, mock.Anything).Return(&mockTpm, nil)

	adapterFactory := NewTpmAdapterFactory(&mockTpmFactory)
	adapter, err := adapterFactory.New()
	if err != nil {
		t.Fatal(err)
	}
	adapter.(*tpmAdapter).withUefiLogs = "/some/invalid/path"

	_, err = adapter.GetEvidence(nil, nil)
	if !errors.Is(err, ErrFailedToReadUEFILogs) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestReadAkCertificateFileFailure(t *testing.T) {
	invalidUri, _ := url.Parse("file://invalid/path")
	_, err := readAkCertificate(invalidUri, nil)
	if !errors.Is(err, ErrReadAkFileFailure) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestReadAkCertificateNvramInvalidHex(t *testing.T) {
	invalidUri, _ := url.Parse("nvram://nothex")
	_, err := readAkCertificate(invalidUri, nil)
	if !errors.Is(err, ErrReadAkNvramInvalidHex) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestReadAkCertificateNvramInvalidHandle(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	invalidUri, _ := url.Parse(fmt.Sprintf("nvram://%x", DefaultAkHandle)) // DefaultAkHandle is not nvram
	_, err = readAkCertificate(invalidUri, tpm)
	if !errors.Is(err, ErrReadAkNvramFailure) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestGetCAIssuerCertificatePositive(t *testing.T) {
	// Any cert will do for "getFx" -- use the TPM's EK certificate
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	ekCertificate, err := tpm.GetEKCertificate(DefaultEkNvIndex)
	if err != nil {
		t.Fatal(err)
	}

	getFx := func(url string) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(ekCertificate.Raw)),
			Header:     make(http.Header),
		}, nil
	}

	issureCert, err := getIssuerCertificate("noimpact", getFx)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, ekCertificate.Raw, issureCert.Raw, "certificates should be equal by DER encoding")
}

func TestGetCAIssuerCertificateHttpError(t *testing.T) {
	getFx := func(url string) (*http.Response, error) {
		return nil, errors.New("unit testing")
	}

	_, err := getIssuerCertificate("noimpact", getFx)
	if !errors.Is(err, ErrIssuerCAHttpError) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestGetCAIssuerCertificateFailureStatusError(t *testing.T) {
	getFx := func(url string) (*http.Response, error) {
		return &http.Response{
			StatusCode: 400, // error code
			Body:       io.NopCloser(bytes.NewReader([]byte{})),
			Header:     make(http.Header),
		}, nil
	}

	_, err := getIssuerCertificate("noimpact", getFx)
	if !errors.Is(err, ErrIssuerCAStatusError) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestParseCertificateBytesPositiveDer(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	ekCertificate, err := tpm.GetEKCertificate(DefaultEkNvIndex)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := parseCertificateBytes(ekCertificate.Raw)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, ekCertificate.Raw, cert.Raw, "certificates should be equal by DER encoding")
}

func TestParseCertificateBytesPositivePem(t *testing.T) {
	// Any cert will do for "getFx" -- use the TPM's EK certificate
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	ekCertificate, err := tpm.GetEKCertificate(DefaultEkNvIndex)
	if err != nil {
		t.Fatal(err)
	}

	var pemBuf bytes.Buffer
	pem.Encode(&pemBuf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ekCertificate.Raw,
	})

	cert, err := parseCertificateBytes(pemBuf.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, ekCertificate.Raw, cert.Raw, "certificates should be equal by DER encoding")
}

func TestParseCertificateBytesBadBytes(t *testing.T) {
	_, err := parseCertificateBytes(make([]byte, 256))
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestParseCertificateBytesBadPem(t *testing.T) {
	// Any cert will do for "getFx" -- use the TPM's EK certificate
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	ekCertificate, err := tpm.GetEKCertificate(DefaultEkNvIndex)
	if err != nil {
		t.Fatal(err)
	}

	var pemBuf bytes.Buffer
	pem.Encode(&pemBuf, &pem.Block{
		Type:  "PUBLIC KEY", // only take "CERTIFICATE"
		Bytes: ekCertificate.Raw,
	})

	_, err = parseCertificateBytes(pemBuf.Bytes())
	if !errors.Is(err, ErrInvalidPemType) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}
