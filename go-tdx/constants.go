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

	TdReportSize   = 1024
	TdQuoteMaxSize = 8192
)

type TdxReportRequest struct {
	ReportData [TdxReportDataLen]byte
	TdReport   [TdxReportLen]byte
}

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
