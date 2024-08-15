/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"testing"
)

func TestCreatPhysicalEK(t *testing.T) {
	tpm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = tpm.CreateEK(testEkHandle)
	if err != nil {
		t.Fatal(err)
	}
}
