/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import "testing"

func TestActivateNotPersistentHandle(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	_, err = tpm.ActivateCredential(DefaultEkHandle, DefaultEkNvIndex, []byte{}, []byte{}) // DefaultEkNvIndex is not a valid persistent handle
	if err != ErrInvalidHandle {
		t.Fail()
	}
}

func TestActivateMissingHandle(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	// handles are not present yet...
	_, err = tpm.ActivateCredential(DefaultEkHandle, DefaultAkHandle, []byte{}, []byte{})
	if err != ErrHandleDoesNotExist {
		t.Fail()
	}
}
