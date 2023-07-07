/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package sgx

import (
	"unsafe"

	"github.com/intel/amber-client/go-client"
)

// sgxAdapter manages SGX Quote collection from SGX enabled platform
type sgxAdapter struct {
	EID            uint64
	uData          []byte
	ReportFunction unsafe.Pointer
}

// NewEvidenceAdapter returns a new SGX Adapter instance
func NewEvidenceAdapter(eid uint64, udata []byte, reportFunction unsafe.Pointer) (client.EvidenceAdapter, error) {
	return &sgxAdapter{
		EID:            eid,
		uData:          udata,
		ReportFunction: reportFunction,
	}, nil
}
