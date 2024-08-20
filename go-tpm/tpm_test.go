/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"math/big"
	"time"

	"github.com/canonical/go-tpm2"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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
	tpmOptions := []TpmOption{}

	if testTpmDevice == nil {
		panic("testTpmDevice connot be nil")
	}
	tpmOptions = append(tpmOptions, WithTpmDeviceType(ParseTpmDeviceType(*testTpmDevice)))

	if testOwnerAuth == nil {
		panic("testOwnerAuth connot be nil")
	}
	tpmOptions = append(tpmOptions, WithTpmOwnerAuth(*testOwnerAuth))

	tpm, err := New(tpmOptions...)
	if err != nil {
		return nil, err
	}

	return tpm, nil
}

func resetTestTpm(tpm TrustedPlatformModule) error {
	t, ok := tpm.(*canonicalTpm)
	if !ok {
		return errors.New("TPM is not a canonical TPM")
	}

	if t.deviceType == Linux {
		return errors.New("Clearing the TPM is not supported on physical TPMs")
	}

	err := t.ctx.Shutdown(tpm2.StartupClear)
	//err := t.ctx.Shutdown(tpm2.StartupState)
	if err != nil && !tpm2.IsTPMError(err, tpm2.ErrorInitialize, tpm2.AnyCommandCode) {
		return errors.Wrap(err, "Failed to shutdown the TPM")
	}

	err = t.ctx.Startup(tpm2.StartupClear)
	if err != nil {
		return errors.Wrap(err, "Failed to clear the TPM")
	}

	return nil
}

func setEkCertificate(tpm TrustedPlatformModule) error {
	t, ok := tpm.(*canonicalTpm)
	if !ok {
		return errors.New("TPM is not a canonical TPM")
	}

	if t.deviceType == Linux {
		return errors.New("Setting the EK certificate is not supported on physical TPMs")
	}

	err := tpm.CreateEK(0x81000800)
	if err != nil {
		return errors.Wrap(err, "Failed to create default EK")
	}

	ekPub, _, _, err := tpm.ReadPublic(0x81000800)
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
