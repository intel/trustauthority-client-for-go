/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import "testing"

func TestQuoteInvalidAkHandle(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	_, _, err = tpm.GetQuote(DefaultEkNvIndex, nil) // DefaultEkNvIndex is not a persistent handle
	if err != ErrInvalidHandle {
		t.Fatalf("unexpected error returned: %v", err)
	}
}

func TestQuoteMissingAkHandle(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	_, _, err = tpm.GetQuote(DefaultAkHandle, nil) // DefaultAkHandle has not been created
	if err != ErrHandleDoesNotExist {
		t.Fatalf("unexpected error returned: %v", err)
	}
}
