/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"testing"
)

func TestQuotePositive(t *testing.T) {
	t.Skip() // TODO:  This test cannot be run unit AK Provisioning is implemented

	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	quote, signature, err := tpm.GetQuote(DefaultAkHandle, []byte{})
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Quote: %d", len(quote))
	t.Logf("Signature: %d", len(signature))
}
