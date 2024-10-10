/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"testing"

	"github.com/pkg/errors"
)

func TestReadPublicPositive(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.CreateEK(testEkHandle)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, err = tpm.ReadPublic(testEkHandle)
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadPublicInvalidHandleType(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	_, _, _, err = tpm.ReadPublic(0x0001)
	if err == nil || !errors.Is(err, ErrInvalidHandle) {
		t.Fatal("Exected ErrInvalidHandle")
	}
}

func TestReadPublicDoesNotExist(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	// don't create EK

	_, _, _, err = tpm.ReadPublic(testEkHandle)
	if err == nil || !errors.Is(err, ErrHandleDoesNotExist) {
		t.Fatal("Expected ErrHandleDoesNotExist")
	}
}
