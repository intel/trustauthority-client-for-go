/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"reflect"
	"testing"
)

func TestValidEkHandle(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	ekNv, err := tpm.NVRead(DefaultEkNvIndex)
	if err != nil {
		t.Fatal(err)
	}

	if len(ekNv) == 0 {
		t.Fatalf("Handle 0x%x should not be read", DefaultAkHandle)
	}
}

func TestNvHandleOutOfRange(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	_, err = tpm.NVRead(0x80000801) // this is not nv handle
	if err != ErrHandleOutOfRange {
		t.Fail()
	}
}

func TestEmptyEkHandle(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	_, err = tpm.NVRead(DefaultEkNvIndex + 1)
	if err != ErrorNvIndexDoesNotExist {
		t.Fail()
	}
}

func TestNvWrite(t *testing.T) {
	len := 256
	testNvHandle := 0x01001899

	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.NVDefine(testNvHandle, len)
	if err != nil {
		t.Fatal(err)
	}

	d := make([]byte, len)
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
