/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"github.com/sirupsen/logrus"
)

// TODO [CASSINI-17044]: Current unit tests are for debugging phyical TPMs and will be
// be updated at a later date.

var (
	testEkHandle = 0x81000F00
	testAkHandle = 0x81000F01
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetReportCaller(true)
}

// TODO [CASSINI-17044]: common functions for resetting, preparing, etc. the TPM for unit tests.
