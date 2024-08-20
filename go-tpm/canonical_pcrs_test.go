/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"testing"
)

// TODO [CASSINI-17044]: Current unit tests are for debugging phyical TPMs and will be
// be updated at a later date.

func TestGetPcrs(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	err = resetTestTpm(tpm)
	if err != nil {
		t.Fatal(err)
	}

	pcrs, err := tpm.GetPcrs()
	if err != nil {
		t.Fatal(err)
	}

	if len(pcrs) <= 0 {
		t.Fail()
	}

	t.Logf("+%v", pcrs)
}
