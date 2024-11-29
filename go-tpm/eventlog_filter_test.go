/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"crypto"
	_ "embed"
	"testing"
)

// Raw /sys/kernel/security/tpm0/binary_bios_measurements file from Azure TDX CVM.
//
//go:embed test_data/binary_bios_measurements20
var binary_bios_measurements20 []byte

func TestAdapterEventFilter20(t *testing.T) {
	eventLogFilter, err := newEventLogFilter(binary_bios_measurements20, defaultPcrSelections...)
	if err != nil {
		t.Fatal(err)
	}

	_, err = eventLogFilter.FilterEventLogs()
	if err != nil {
		t.Fatal(err)
	}
}

//go:embed test_data/binary_bios_measurements12
var binary_bios_measurements12 []byte

func TestAdapterEventFilter12(t *testing.T) {
	eventLogFilter, err := newEventLogFilter(binary_bios_measurements12, []PcrSelection{
		{
			Hash: crypto.SHA1,
			Pcrs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
		},
	}...)
	if err != nil {
		t.Fatal(err)
	}

	_, err = eventLogFilter.FilterEventLogs()
	if err != nil {
		t.Fatal(err)
	}
}
