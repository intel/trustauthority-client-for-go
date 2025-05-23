/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/pkg/errors"
)

// This unit tests integrates the end-to-end flow of provisioning an AK
// on a new TPM and getting a TPM quote.  It is similar to tdx-cli/cmd/provision_ak.go.
//
// Things tested this unit test:
//   - TPM is provisioned with EK/AK
//   - The AES key from ITA can be decrypted using ActivateCredential (provided EK pub
//     and AK data as input).  Assume ITA generates can a valid AK cert (not tested).
//   - A TPM quote can be generated and verified against the AK public key.
func TestEndToEnd(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = provisionTestAk(tpm)
	if err != nil {
		t.Fatal(err)
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

	akPub, _, _, err := tpm.ReadPublic(testAkHandle)
	if err != nil {
		t.Fatal(err)
	}

	err = rsa.VerifyPSS(akPub.(*rsa.PublicKey), crypto.SHA256, quoteDigest, s.Signature.RSAPSS.Sig, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func provisionTestAk(tpm TrustedPlatformModule) error {
	err := tpm.CreateEK(testEkHandle)
	if err != nil {
		return fmt.Errorf("failed to create EK: %w", err)
	}

	err = tpm.CreateAK(testAkHandle, testEkHandle)
	if err != nil {
		return fmt.Errorf("failed to create AK: %w", err)
	}

	_, akTpmtPublic, _, err := tpm.ReadPublic(testAkHandle)
	if err != nil {
		return fmt.Errorf("failed to read AK public: %w", err)
	}

	// Get the EK certificate
	ekCert, err := tpm.GetEKCertificate(DefaultEkNvIndex)
	if err != nil {
		return fmt.Errorf("failed to get EK certificate: %w", err)
	}

	// Simulate the ITA making a request to the connector to get an AK certificate
	ekPub, ok := ekCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("failed to cast the ek public to rsa.PublicKey")
	}

	fakeAesKey := []byte("decafbad")
	credentialBlob, secret, err := makeCredential(ekPub, akTpmtPublic, fakeAesKey)
	if err != nil {
		return fmt.Errorf("make credential failed: %w", err)
	}

	// Decrypt aes key that encrypts payload
	aesKey, err := tpm.ActivateCredential(testEkHandle, testAkHandle, credentialBlob, secret)
	if err != nil {
		return fmt.Errorf("activate credential failed: %w", err)
	}

	// The AK certificate is not critical to this unit-test (it is verified by the cluster).
	// Just make sure the aesKey returned from ActiveCredential matches what was encrypted by
	// makecredential (and assume that it can be used to decrypt the AK cert created by ITA).
	if bytes.Compare(fakeAesKey, aesKey) != 0 {
		return errors.New("Incorrect aes key")
	}

	return nil
}

// This simulates the Trust Authority's GetAKCertificate method
func makeCredential(rsaPub *rsa.PublicKey, tpmtPublic []byte, key []byte) ([]byte, []byte, error) {
	tpm2Key := &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs: tpm2.AttrFixedTPM |
			tpm2.AttrFixedParent |
			tpm2.AttrSensitiveDataOrigin |
			tpm2.AttrAdminWithPolicy |
			tpm2.AttrRestricted |
			tpm2.AttrDecrypt,
		AuthPolicy: defaultAuthPolicySha256,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits: &tpm2.SymKeyBitsU{
						Sym: 128,
					},
					Mode: &tpm2.SymModeU{
						Sym: tpm2.SymModeCFB,
					},
				},
				Scheme: tpm2.RSAScheme{
					Scheme:  tpm2.RSASchemeNull,
					Details: &tpm2.AsymSchemeU{},
				},
				KeyBits:  uint16(rsaPub.N.BitLen()),
				Exponent: 0,
			},
		},
		Unique: &tpm2.PublicIDU{
			RSA: rsaPub.N.Bytes(),
		},
	}

	var tp tpm2.Public
	_, err := mu.UnmarshalFromBytes(tpmtPublic, &tp)
	if err != nil {
		return nil, nil, err
	}

	akName, err := tp.ComputeName()
	if err != nil {
		return nil, nil, err
	}

	credentialBlob, secret, err := objectutil.MakeCredential(rand.Reader, tpm2Key, key, akName)
	if err != nil {
		return nil, nil, err
	}

	return credentialBlob, secret, nil
}
