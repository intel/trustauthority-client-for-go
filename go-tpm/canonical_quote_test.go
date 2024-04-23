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
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/policyutil"
)

// TODO [CASSINI-17044]: Current unit tests are for debugging phyical TPMs and will be
// be updated at a later date.

func TestQuotePhysical(t *testing.T) {
	tpm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	quote, signature, err := tpm.GetQuote(DefaultAkHandle, []byte{})
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Quote: %s", quote)
	t.Logf("Signature: %s", signature)
}

// This is a debugging tool, not a unit test and assumes EK/AK/AK-Cert
// have been provisioned
//
// Get quote/signature/pcrs/ak-pub from TPM
// Verify AK cert: not included
// Verify quote: quote matches sig/ak-pub
// Verify PCRs: quote digest matches pcr digest
func TestQuoteDigest(t *testing.T) {
	tpm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	// get AK certificate from nvram
	akDer, err := tpm.NVRead(0x01000800)
	if err != nil {
		t.Fatal(err)
	}

	akCert, err := x509.ParseCertificate(akDer)
	if err != nil {
		t.Fatal(err)
	}

	// get a quote/signature
	quote, signature, err := tpm.GetQuote(DefaultAkHandle, []byte{})
	if err != nil {
		t.Fatal(err)
	}

	var sig tpm2.Signature
	_, err = mu.UnmarshalFromBytes(signature, &sig)
	if err != nil {
		t.Fatal(err)
	}

	hash := sha256.New()
	_, err = hash.Write(quote)
	if err != nil {
		t.Fatal(err)
	}
	pcrsDigest := hash.Sum(nil)

	// verify quote data is signed by ak pub
	err = rsa.VerifyPSS(akCert.PublicKey.(*rsa.PublicKey), crypto.SHA256, pcrsDigest, sig.Signature.RSAPSS.Sig, nil)
	if err != nil {
		t.Fatal(err)
	}

	// compare the quote digest against the digest of the PCRs
	var attest tpm2.Attest
	_, err = mu.UnmarshalFromBytes(quote, &attest)
	if err != nil {
		t.Fatal(err)
	}

	pcrs, err := tpm.GetPcrs()
	if err != nil {
		t.Fatal(err)
	}

	var pcrValues tpm2.PCRValues
	_, err = mu.UnmarshalFromBytes(pcrs, &pcrValues)
	if err != nil {
		t.Fatal(err)
	}

	_, digest, err := policyutil.ComputePCRDigestFromAllValues(tpm2.HashAlgorithmSHA256, pcrValues)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(attest.Attested.Quote.PCRDigest, digest) {
		t.Fail()
	}
}
