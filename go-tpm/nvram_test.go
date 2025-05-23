/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"reflect"
	"testing"

	"github.com/pkg/errors"
)

func TestNvReadPositive(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	// read the preinstalled EK NV index
	ekNv, err := tpm.NVRead(DefaultEkNvIndex)
	if err != nil {
		t.Fatal(err)
	}

	if len(ekNv) == 0 {
		t.Fatalf("Handle 0x%x should not be read", DefaultAkHandle)
	}
}

func TestNvReadHandleOutOfRange(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	_, err = tpm.NVRead(0x80000801) // this is not a valid nv handle
	if err != ErrHandleOutOfRange {
		t.Fail()
	}
}

func TestNvReadMissingHandle(t *testing.T) {
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

func TestNvWritePositive(t *testing.T) {
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

func TestNvWriteHandleOutOfRange(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.NVWrite(maxNvHandle+1, []byte{})
	if !errors.Is(err, ErrHandleOutOfRange) {
		t.Fail()
	}
}

func TestNvWriteMissingHandle(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.NVWrite(minNvHandle, make([]byte, 256))
	if !errors.Is(err, ErrorNvIndexDoesNotExist) {
		t.Fail()
	}
}

func TestNvWriteSizeCheck(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.NVWrite(DefaultEkNvIndex, []byte{})
	if !errors.Is(err, ErrNvInvalidSize) {
		t.Fail()
	}

	err = tpm.NVWrite(DefaultEkNvIndex, make([]byte, maxNvSize+1))
	if !errors.Is(err, ErrNvInvalidSize) {
		t.Fail()
	}
}

func TestNvDeleteHandleOutOfRange(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.NVDelete(maxNvHandle + 1)
	if !errors.Is(err, ErrHandleOutOfRange) {
		t.Fail()
	}
}

func TestNvDeleteMissingHandle(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.NVDelete(minNvHandle)
	if !errors.Is(err, ErrorNvIndexDoesNotExist) {
		t.Fail()
	}
}

func TestNvDefineHandleOutOfRange(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.NVDefine(maxNvHandle+1, 256)
	if !errors.Is(err, ErrHandleOutOfRange) {
		t.Fail()
	}
}

func TestNvDefineSizeCheck(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.NVDefine(minNvHandle, 0)
	if !errors.Is(err, ErrNvInvalidSize) {
		t.Fail()
	}

	err = tpm.NVDefine(minNvHandle, maxNvSize+1)
	if !errors.Is(err, ErrNvInvalidSize) {
		t.Fail()
	}
}

func TestNvDefineHandlePresent(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.NVDefine(minNvHandle, 256)
	if err != nil {
		t.Fatal(err)
	}

	// try to define the same handle again
	err = tpm.NVDefine(minNvHandle, 256)
	if !errors.Is(err, ErrExistingHandle) {
		t.Fail()
	}
}

func TestNvExistsHandleOutOfRange(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	if tpm.NVExists(0x80000801) {
		t.Fatal("Handle 0x80000801 should return false")
	}
}

func TestNvExistsNotNVHandle(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	if tpm.NVExists(DefaultAkHandle) {
		t.Fatal("should return false")
	}
}
