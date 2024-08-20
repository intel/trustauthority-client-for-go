/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"testing"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/pkg/errors"
)

// This unit tests integrates the end-to-end flow of provisioning an AK
// on a new TPM and getting a TPM quote.  It is similar to tdx-cli/cmd/provision_ak.go.

// Things to test in this unit test:
//   - TPM is provisioned with EK/AK
//   - The AES key from ITA can be decrypted using ActivateCredential (provided EK pub
//     and AK data as input).  Assume ITA generates can a valid AK cert (not tested).
//   - A TPM quote can be generated and verified against the AK public key.
func TestEndToEnd(t *testing.T) {
	// d := "linux"
	// testTpmDevice = &d
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = resetTestTpm(tpm)
	if err != nil {
		t.Fatal(err)
	}

	err = setEkCertificate(tpm)
	if err != nil {
		t.Fatal(err)
	}

	err = tpm.CreateEK(testEkHandle)
	if err != nil {
		t.Fatal(err)
	}

	err = tpm.CreateAK(testAkHandle, testEkHandle)
	if err != nil {
		t.Fatal(err)
	}

	akPub, akTpmtPublic, _, err := tpm.ReadPublic(testAkHandle)
	if err != nil {
		t.Fatal(err)
	}

	// Get the EK certificate
	ekCert, err := tpm.GetEKCertificate(DefaultEkNvIndex)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the ITA making a request to the connector to get an AK certificate
	ekPub, ok := ekCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal(errors.New("Failed to cast the ek public to rsa.PublicKey"))
	}

	fakeAesKey := []byte("decafbad")
	credentialBlob, secret, err := makeCredential(ekPub, akTpmtPublic, fakeAesKey)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt aes key that encrypts payload
	aesKey, err := tpm.ActivateCredential(testEkHandle, testAkHandle, credentialBlob, secret)
	if err != nil {
		t.Fatal(err)
	}

	// The AK certificate is not critical to this unit-test (it is verified by the cluster).
	// Just make sure the aesKey returned from ActiveCredential matches what was encrypted by
	// makecredential (and assume that it can be used to decrypt the AK cert created by ITA).
	if bytes.Compare(fakeAesKey, aesKey) != 0 {
		t.Fatal("Incorrect aes key")
	}

	// now generate a TPM quote and verify it against the AK public (again, simulating ITA)
	quote, signature, err := tpm.GetQuote(testAkHandle, nil, defaultPcrSelections...)
	if err != nil {
		t.Fatal(err)
	}

	h := crypto.SHA256.New()
	_, err = h.Write(quote)
	if err != nil {
		t.Fatal(err)
	}
	quoteDigest := h.Sum(nil)

	var s tpm2.Signature
	_, err = mu.UnmarshalFromBytes(signature, &s)
	if err != nil {
		t.Fatal(err)
	}

	err = rsa.VerifyPSS(akPub.(*rsa.PublicKey), crypto.SHA256, quoteDigest, s.Signature.RSAPSS.Sig, nil)
	if err != nil {
		t.Fatal(err)
	}
}
