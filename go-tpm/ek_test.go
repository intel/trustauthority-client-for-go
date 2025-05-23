/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"testing"
)

func TestCreateEkOutOfRange(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.CreateEK(minPersistentHandle - 1)
	if err == nil || err != ErrHandleOutOfRange {
		t.Fatal(err)
	}

	err = tpm.CreateEK(maxPersistentHandle + 1)
	if err == nil || err != ErrHandleOutOfRange {
		t.Fatal(err)
	}
}

func TestCreateEkHandleType(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	// try to create the same EK handle twice...
	err = tpm.CreateEK(DefaultEkHandle)
	if err != nil {
		t.Fatal(err)
	}

	err = tpm.CreateEK(DefaultEkHandle)
	if err == nil || err != ErrExistingHandle {
		t.Fatal(err)
	}
}
