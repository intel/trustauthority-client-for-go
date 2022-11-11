/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package sgx

import (
	"unsafe"
)

type SgxAdapter struct {
	EID            uint64
	uData          []byte
	ReportFunction unsafe.Pointer
}

func NewAdapter(eid uint64, udata []byte, reportFunction unsafe.Pointer) (*SgxAdapter, error) {
	return &SgxAdapter{
		EID:            eid,
		uData:          udata,
		ReportFunction: reportFunction,
	}, nil
}
