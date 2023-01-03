/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

// TdxAdapter manages TDX Quote collection from TDX enabled platform
type TdxAdapter struct {
	uData       []byte
	EvLogParser EventLogParser
}

// NewAdapter returns a new TDX Adapter instance
func NewAdapter(udata []byte, evLogParser EventLogParser) (*TdxAdapter, error) {
	return &TdxAdapter{
		uData:       udata,
		EvLogParser: evLogParser,
	}, nil
}
