//go:build !test

/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"github.com/intel/trustauthority-client/go-connector"
)

// TdxAdapter manages TDX Quote collection from TDX enabled platform
type tdxAdapter struct {
	uData       []byte
	EvLogParser EventLogParser
}

// NewEvidenceAdapter returns a new TDX Adapter instance
func NewEvidenceAdapter(udata []byte, evLogParser EventLogParser) (connector.EvidenceAdapter, error) {
	return &tdxAdapter{
		uData:       udata,
		EvLogParser: evLogParser,
	}, nil
}
