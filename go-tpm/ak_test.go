/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"testing"

	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/pkg/errors"
)

var minPersistentHandle = 0x81000000
var maxPersistentHandle = 0x81FFFFFF

func TestCreateAkInvalidHandle(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.CreateAK(minPersistentHandle-1, DefaultEkHandle)
	if !errors.Is(err, ErrHandleOutOfRange) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestCreateAkAlreadyExists(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.CreateEK(DefaultEkHandle)
	if err != nil {
		t.Fatal(err)
	}

	err = tpm.CreateAK(DefaultAkHandle, DefaultEkHandle)
	if err != nil {
		t.Fatal(err)
	}

	// try again, it should fail
	err = tpm.CreateAK(DefaultAkHandle, DefaultEkHandle)
	if !errors.Is(err, ErrExistingHandle) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestCreateAkNotPersistentEk(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	// try again, it should fail
	err = tpm.CreateAK(DefaultAkHandle, DefaultEkNvIndex) // DefaultEkNvIndex is not a persistent handle
	if !errors.Is(err, ErrInvalidHandle) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestCreateAkEkDoesNotExist(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	// try again, it should fail
	err = tpm.CreateAK(DefaultAkHandle, DefaultEkHandle) // DefaultEkHandle has not been created yet
	if !errors.Is(err, ErrHandleDoesNotExist) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestCreateAkTemplatePositive(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.CreateAkFromTemplate(DefaultAkHandle, getTestAkTemplate(t))
	if err != nil {
		t.Fatal(err)
	}

	pubKey, _, _, err := tpm.ReadPublic(DefaultAkHandle)
	if err != nil {
		t.Fatal(err)
	}

	if pubKey == nil {
		t.Fatal("AK public key is nil")
	}
}

func TestCreateAkTemplateInvalidHandleRange(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.CreateAkFromTemplate(minPersistentHandle-1, getTestAkTemplate(t))
	if !errors.Is(err, ErrHandleOutOfRange) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestCreateAkTemplateAlreadyExists(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.CreateAkFromTemplate(DefaultAkHandle, getTestAkTemplate(t))
	if err != nil {
		t.Fatal(err)
	}

	// try again, it should fail
	err = tpm.CreateAkFromTemplate(DefaultAkHandle, getTestAkTemplate(t))
	if !errors.Is(err, ErrExistingHandle) {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestCreateAkTemplateBadBits(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.CreateAkFromTemplate(DefaultAkHandle, make([]byte, 256))
	if err == nil {
		t.Fatalf("expected template marshaling error")
	}
}

func getTestAkTemplate(t *testing.T) []byte {
	options := []objectutil.PublicTemplateOption{objectutil.WithoutDictionaryAttackProtection()}
	akTemplate := objectutil.NewRSAAttestationKeyTemplate(options...)
	akTemplateBytes, err := mu.MarshalToBytes(akTemplate)
	if err != nil {
		t.Fatal(err)
	}
	return akTemplateBytes
}
