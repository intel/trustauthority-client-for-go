/*
 *   Copyright (c) 2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package gramine

import (
	"github.com/intel/trustauthority-client/go-connector"
)

type gramineAdapter struct {
	uData []byte
}

func NewEvidenceAdapter(udata []byte) (connector.EvidenceAdapter, error) {
	return &gramineAdapter{
		uData: udata,
	}, nil
}
