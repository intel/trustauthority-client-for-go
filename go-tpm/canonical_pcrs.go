/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"fmt"
	"math"

	"github.com/pkg/errors"
)

// GetPcrs returns the "flattened", concatenated, contiguous PCR measurements
// for SHA-256 banks 0-23 (in index order).  This is similar to the pcr values
// returned in tpm2_quote when '-F values' options are provided.  If 'selection'
// is not provided, then all sha1 and sha256 banks are included in the results.
func (tpm *canonicalTpm) GetPcrs(selection ...PcrSelection) ([]byte, error) {
	pcrSelection, err := toTpm2PcrSelectionList(selection...)
	if err != nil {
		return nil, err
	}

	_, pcrValues, err := tpm.ctx.PCRRead(pcrSelection, nil)
	if err != nil {
		return nil, err
	}

	selectionList, err := pcrValues.SelectionList()
	if err != nil {
		return nil, err
	}

	// flatten the results into contigous, index ordered binary (no alg headers, etc.)
	results := []byte{}
	for _, s := range selectionList {
		if _, ok := pcrValues[s.Hash]; !ok {
			return nil, errors.Errorf("PCR values did not contain don't contain digests for PCR bank %v", s.Hash)
		}

		bmp, err := s.Select.ToBitmap(math.MaxUint8)
		if err != nil {
			return nil, fmt.Errorf("Invalid selection: %w", err)
		}
		sel := bmp.ToPCRs()

		for _, i := range sel {
			d, ok := pcrValues[s.Hash][i]
			if !ok {
				return nil, fmt.Errorf("PCR values did not contain a digest for PCR%d in bank %v", i, s.Hash)
			}

			results = append(results, d...)
		}
	}

	return results, nil
}
