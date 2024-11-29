/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package aztdx

const (
	azAkHandle        = 0x81000003
	azRuntimeReadIdx  = 0x1400001
	azRuntimeWriteIdx = 0x1400002
)

// This is the local URL used on Azure to get a TDX quote from a TDX report.
var tdxReportUrl = "http://169.254.169.254"
