/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"reflect"
	"testing"

	"github.com/canonical/go-tpm2"
)

// TODO [CASSINI-17044]: Current unit tests are for debugging phyical TPMs and will be
// be updated at a later date.

func TestValidEkHandle(t *testing.T) {
	tpm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	ekNv, err := tpm.NVRead(DefaultEkNvIndex)
	if err != nil {
		t.Fatal(err)
	}

	if len(ekNv) == 0 {
		t.Fatalf("Handle %x should not be read", DefaultAkHandle)
	}
}

func TestInvalidEkHandle(t *testing.T) {
	tpm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	_, err = tpm.NVRead(0x80000801) // this is not nv handle
	if err != ErrInvalidHandle {
		t.Fail()
	}
}

func TestEmptyEkHandle(t *testing.T) {
	tpm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	nv, err := tpm.NVRead(DefaultEkNvIndex + 1)
	if _, ok := err.(*tpm2.TPMHandleError); !ok {
		t.Fatalf("Expected error ErrHandleError but got %s", err.Error())
	}

	if nv != nil {
		t.Fail()
	}
}

func TestNvWrite(t *testing.T) {
	testNvHandle := 0x01000899
	tpm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	d := make([]byte, 4096)

	err = tpm.NVWrite(testNvHandle, d)
	if err != nil {
		t.Fatal(err)
	}

	nv, err := tpm.NVRead(testNvHandle)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(d, nv) {
		t.Fail()
	}

	err = tpm.NVDelete(testNvHandle)
	if err != nil {
		t.Fatal(err)
	}
}
