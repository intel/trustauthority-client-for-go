/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
)

var fakeAesKey = "decafbad"

func TestPhysicalActivateCredential(t *testing.T) {
	tpm, err := New()
	if err != nil {
		t.Fatal(err)
	}

	_, tpmtPublic, _, err := tpm.ReadPublic(testAkHandle)
	if err != nil {
		t.Fatal(err)
	}

	ekCert, err := tpm.GetEKCertificate(DefaultEkNvIndex)
	if err != nil {
		t.Fatal(err)
	}

	tpm.Close() // force the tpm to close

	rsaPub, ok := ekCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal(errors.New("Failed to cast the ek public to rsa.PublicKey"))
	}

	credentialBlob, secret, err := makeCredential(rsaPub, tpmtPublic)
	if err != nil {
		t.Fatal(err)
	}

	tpm, err = New()
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := tpm.ActivateCredential(testEkHandle, testAkHandle, credentialBlob, secret)
	if err != nil {
		t.Fatal(err)
	}
	tpm.Close()

	t.Logf("%+v", decrypted)
	if string(decrypted) != fakeAesKey {
		t.Failed()
	}
}

// This simulates the Trust Authority's GetAKCertificate method
func makeCredential(rsaPub *rsa.PublicKey, tpmtPublic []byte) ([]byte, []byte, error) {
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

	credentialBlob, secret, err := objectutil.MakeCredential(rand.Reader, tpm2Key, []byte(fakeAesKey), akName)
	if err != nil {
		return nil, nil, err
	}

	return credentialBlob, secret, nil
}
