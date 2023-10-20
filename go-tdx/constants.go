//go:build !test

/*
 *   Copyright (c) 2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

const (
	TdxReportDataLen = 64
	TdxReportLen     = 1024
	TdxAttestDevPath = "/dev/tdx_guest"

	TdxGetReportSuccess = 0
	TdxGetReportFailed  = -1

	ReqBufSize = 4 * 4 * 1024
)

const (
	IocNrBits            = 8
	IocTypeBits          = 8
	IocSizeBits          = 14
	IocNrShift           = 0
	IocWrite     uintptr = 1
	IocRead      uintptr = 2
	IocTypeShift         = IocNrShift + IocNrBits
	IocSizeShift         = IocTypeShift + IocTypeBits
	IocDirshift          = IocSizeShift + IocSizeBits
)
