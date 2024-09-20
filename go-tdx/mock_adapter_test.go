/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import "testing"

func TestMockCoverage(t *testing.T) {
	adapter, _ := NewTdxAdapter(nil, nil)
	_, _ = adapter.CollectEvidence(nil)

	adapter2, _ := NewCompositeEvidenceAdapter(nil)
	_ = adapter2.GetEvidenceIdentifier()
	_, _ = adapter2.GetEvidence(nil, nil)
}
