/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import "crypto"

const (
	maxNvSize        = 1024 * 8 // 8k
	DefaultEkNvIndex = 0x01c00002
	DefaultEkHandle  = 0x81000800
	DefaultAkHandle  = 0x81000801

	// min/max "owner" nv handles
	// see "Registry of Reserved TPM 2.0 Handles and Localities" section 2.2.2
	minNvHandle = 0x01000000
	maxNvHandle = 0x01C2FFFF

	DefaultImaPath          = "/sys/kernel/security/ima/ascii_runtime_measurements"
	DefaultUefiEventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements"

	// TCG event log constants
	specIdEvent03   = "Spec ID Event03"
	startupLocality = "StartupLocality"
)

var (
	defaultPcrSelections = []PcrSelection{
		{
			Hash: crypto.SHA256,
			Pcrs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
		},
	}
)

// This is a well known bytes uses for the endorsement's authorization policy
var defaultAuthPolicySha256 = []byte{
	0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90,
	0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E,
	0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
	0x69, 0xAA,
}
