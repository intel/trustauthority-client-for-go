/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"math/big"
	"testing"
	"time"

	"github.com/canonical/go-tpm2"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

// These variables allow developers to change the settings for unit tests.
// ex. go test -v -run TestGetPcrs -tpm-device linux -tpm-owner-auth "owner"
var (
	testTpmDevice = flag.String("tpm-device", "mssim", "Determines the TPM device to use for testing")
	testOwnerAuth = flag.String("tpm-owner-auth", "", "Determines the TPM device to use for testing")
)

var (
	testEkHandle = 0x81000F00
	testAkHandle = 0x81000F01
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetReportCaller(true)
}

// newTestTpm creates a new TPM object for unit tests.
func newTestTpm() (TrustedPlatformModule, error) {

	if testTpmDevice == nil {
		panic("testTpmDevice connot be nil")
	}

	tpmDevice, err := ParseTpmDeviceType(*testTpmDevice)
	if err != nil {
		panic("Failed to parse tpm device")
	}

	tpm, err := NewTpmFactory().New(tpmDevice, *testOwnerAuth)
	if err != nil {
		return nil, err
	}

	if *testTpmDevice == mssimString {
		err = resetTestTpm(tpm)
		if err != nil {
			return nil, err
		}
	}

	return tpm, nil
}

// The unit tests share a single instance of a running simulator that is
// started in Makefile.  For unit tests to work, the simulator needs to be initialized
// (startup) and have an EK certificate.  This function manages the state of the
// simulator as follows...
//   - If the TPM has just been started and not used, initialize the TPM
//   - If the TPM has been already used (initialized), then clear it.
//   - Set the EK certificate
func resetTestTpm(tpm TrustedPlatformModule) error {

	t, ok := tpm.(*trustedPlatformModule)
	if !ok {
		return errors.New("TPM is not a trustedPlatformModule")
	}

	if t.deviceType == TpmDeviceLinux {
		return errors.New("Clearing the TPM is not supported on physical TPMs")
	}

	tpmInitialized := false
	capability, err := t.ctx.GetCapability(tpm2.CapabilityTPMProperties, uint32(tpm2.PropertyStartupClear), 1, nil)
	if err != nil && tpm2.IsTPMError(err, tpm2.ErrorInitialize, tpm2.AnyCommandCode) {
		tpmInitialized = false
	} else if err != nil {
		return errors.New("Unkown error getting TPM properties")
	} else {
		tpmProperties := capability.Data.TPMProperties
		if tpmProperties == nil {
			return errors.New("Failed to get TPM properties")
		}

		for _, prop := range tpmProperties {
			if prop.Property == tpm2.PropertyStartupClear && prop.Value == 0x8000000f {
				tpmInitialized = true
				break
			}
		}

		// property was not found in previous loop
		if !tpmInitialized {
			return errors.New("Failed to determine startup state of TPM")
		}
	}

	if !tpmInitialized {
		// TPM has not been initialized, start it
		err = t.ctx.Startup(tpm2.StartupClear)
		if err != nil {
			return errors.Wrap(err, "Failed to clear the TPM")
		}
	} else {
		// TPM has been initialized, reset it to clear state
		err = t.ctx.Clear(t.ctx.PlatformHandleContext(), nil)
		if err != nil {
			return errors.Wrap(err, "Failed to clear the TPM")
		}

		err = t.ctx.Shutdown(tpm2.StartupState)
		if err != nil && !tpm2.IsTPMError(err, tpm2.ErrorInitialize, tpm2.AnyCommandCode) {
			return errors.Wrap(err, "Failed to shutdown the TPM")
		}
	}

	// the TPM is now in a clear state, set the EK certificate
	err = setEkCertificate(tpm)
	if err != nil {
		return err
	}

	return nil
}

var defaultEkHandle = 0x81000000

func setEkCertificate(tpm TrustedPlatformModule) error {
	t, ok := tpm.(*trustedPlatformModule)
	if !ok {
		return errors.New("TPM is not a canonical TPM")
	}

	if t.deviceType == TpmDeviceLinux {
		return errors.New("Setting the EK certificate is not supported on physical TPMs")
	}

	err := tpm.CreateEK(defaultEkHandle)
	if err != nil {
		return errors.Wrap(err, "Failed to create default EK")
	}

	ekPub, _, _, err := tpm.ReadPublic(defaultEkHandle)
	if err != nil {
		return errors.Wrap(err, "Failed to get default EK public")
	}

	ekPubRsa := ekPub.(*rsa.PublicKey)

	pkixName := pkix.Name{
		Organization:  []string{"Intel"},
		Country:       []string{"US"},
		Province:      []string{""},
		Locality:      []string{"Santa Clara"},
		StreetAddress: []string{"2200 Mission College Blvd."},
		PostalCode:    []string{"95054"},
	}

	//
	// Generate a self signed root CA
	//
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048) // 2048 used in default EK template
	if err != nil {
		return err
	}

	rootCaTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2020),
		Subject:               pkixName,
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	//
	// Create an EK Certificate and sign it with the root CA
	//
	ekCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject:      pkixName,
		NotBefore:    time.Now().AddDate(-1, 0, 0),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	ekCertificateBytes, err := x509.CreateCertificate(rand.Reader, &ekCertTemplate, &rootCaTemplate, ekPubRsa, caPrivateKey)
	if err != nil {
		return err
	}

	//
	// Write the EK certificate to the TPM's nvram at the standard EK index
	//
	if tpm.NVExists(DefaultEkNvIndex) {
		err = tpm.NVDelete(DefaultEkNvIndex)
		if err != nil {
			return errors.Wrap(err, "Failed to undefine the EK NV index")
		}
	}

	err = tpm.NVDefine(DefaultEkNvIndex, len(ekCertificateBytes))
	if err != nil {
		return errors.Wrap(err, "Failed to define the EK NV index")
	}

	err = tpm.NVWrite(DefaultEkNvIndex, ekCertificateBytes)
	if err != nil {
		return errors.Wrap(err, "Failed to write EK NV index")
	}

	return nil
}

func TestTpmParseDevice(t *testing.T) {
	testData := []struct {
		testName       string
		deviceString   string
		expectedDevice TpmDeviceType
		expectError    bool
	}{
		{
			"Test mssim device",
			mssimString,
			TpmDeviceMSSIM,
			false,
		},
		{
			"Test linux device",
			linuxString,
			TpmDeviceLinux,
			false,
		},
		{
			"Test unknown device",
			"xyz",
			TpmDeviceUnknown,
			true,
		},
	}

	for _, td := range testData {
		t.Run(td.testName, func(t *testing.T) {
			device, err := ParseTpmDeviceType(td.deviceString)
			if !td.expectError && err != nil {
				// not expecting an error but got one
				t.Fatal(err)
			} else if td.expectError && err == nil {
				// expecting an error but got none
				t.Fatal("Expected an error")
			} else if td.expectError && err != nil {
				// expecting an error and got one
				return
			}

			if device != td.expectedDevice {
				t.Fatalf("Expected device %v, got %v", td.expectedDevice, device)
			}

			if device.String() != td.deviceString {
				t.Fatalf("Expected device %s, got %s", td.deviceString, device.String())
			}
		})
	}
}

//------------------------------------------------------------------------------------------
// T P M   M O C K S
//------------------------------------------------------------------------------------------

// MockTpm
type MockTpm struct {
	mock.Mock
}

func (m *MockTpm) CreateEK(ekHandle int) error {
	args := m.Called(ekHandle)
	return args.Error(0)
}

func (m *MockTpm) CreateAK(akHandle int, ekHandle int) error {
	args := m.Called(ekHandle, ekHandle)
	return args.Error(0)
}

func (m *MockTpm) CreateAkFromTemplate(akHandle int, template []byte) error {
	args := m.Called(akHandle, template)
	return args.Error(0)
}

func (m *MockTpm) ActivateCredential(ekHandle int, akHandle int, credentialBlob []byte, secret []byte) ([]byte, error) {
	args := m.Called(ekHandle, akHandle, credentialBlob, secret)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockTpm) NVRead(nvHandle int) ([]byte, error) {
	args := m.Called(nvHandle)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockTpm) NVWrite(nvHandle int, data []byte) error {
	args := m.Called(nvHandle, data)
	return args.Error(0)
}

func (m *MockTpm) NVExists(nvHandle int) bool {
	args := m.Called(nvHandle)
	return args.Get(0).(bool)
}

func (m *MockTpm) NVDefine(nvHandle int, len int) error {
	args := m.Called(nvHandle, len)
	return args.Error(0)
}

func (m *MockTpm) NVDelete(nvHandle int) error {
	args := m.Called(nvHandle)
	return args.Error(0)
}

func (m *MockTpm) ReadPublic(handle int) (crypto.PublicKey, []byte, []byte, error) {
	args := m.Called(handle)
	return args.Get(0).(crypto.PublicKey), args.Get(1).([]byte), args.Get(2).([]byte), args.Error(3)
}

func (m *MockTpm) GetEKCertificate(nvIndex int) (*x509.Certificate, error) {
	args := m.Called(nvIndex)
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

func (m *MockTpm) GetQuote(akHandle int, nonce []byte, selection ...PcrSelection) ([]byte, []byte, error) {
	args := m.Called(akHandle, nonce, selection)
	return args.Get(0).([]byte), args.Get(1).([]byte), args.Error(2)
}

func (m *MockTpm) GetPcrs(selection ...PcrSelection) ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockTpm) HandleExists(handle int) bool {
	args := m.Called(handle)
	return args.Get(0).(bool)
}

func (m *MockTpm) Close() {
	return
}

// MockTpmFactory
type MockTpmFactory struct {
	mock.Mock
}

func (m *MockTpmFactory) New(deviceType TpmDeviceType, ownerAuth string) (TrustedPlatformModule, error) {
	args := m.Called(deviceType, ownerAuth)
	return args.Get(0).(TrustedPlatformModule), args.Error(1)
}
