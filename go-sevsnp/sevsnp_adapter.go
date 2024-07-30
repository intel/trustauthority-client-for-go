//go:build !test

/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package sevsnp

import (
	"github.com/intel/trustauthority-client/go-connector"
)

// sevsnpAdapter manages sevsnp report collection from sevsnp enabled platform
type sevsnpAdapter struct {
	uData []byte
}

// NewEvidenceAdapter returns a new sevsnp Adapter instance
func NewEvidenceAdapter(udata []byte) (connector.EvidenceAdapter, error) {
	return &sevsnpAdapter{
		uData: udata,
	}, nil
}
