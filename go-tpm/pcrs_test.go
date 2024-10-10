/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"testing"
)

func TestPcrsRead(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	pcrs, err := tpm.GetPcrs()
	if err != nil {
		t.Fatal(err)
	}

	if len(pcrs) <= 0 {
		t.Fail()
	}
}
