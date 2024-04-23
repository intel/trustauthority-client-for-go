/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"crypto"
	"sort"

	"github.com/canonical/go-tpm2"
	"github.com/pkg/errors"
)

// toTpm2PcrSelectionList takes in an array of PcrSelection structs and converts them to a
// tpm2.PCRSelectionList.  If no selection is provided, the defaultPcrSelections is used.
func toTpm2PcrSelectionList(selection ...PcrSelection) (tpm2.PCRSelectionList, error) {
	var selectedPcrs []PcrSelection
	var pcrSelectionList tpm2.PCRSelectionList

	if len(selection) == 0 {
		selectedPcrs = defaultPcrSelections
	} else {
		selectedPcrs = selection
		for _, s := range selectedPcrs {
			sort.Ints(s.Pcrs)
		}
	}

	for _, selected := range selectedPcrs {
		var algorithmId tpm2.HashAlgorithmId
		switch selected.Hash {
		case crypto.SHA1:
			algorithmId = tpm2.HashAlgorithmSHA1
		case crypto.SHA256:
			algorithmId = tpm2.HashAlgorithmSHA256
		case crypto.SHA384:
			algorithmId = tpm2.HashAlgorithmSHA384
		case crypto.SHA512:
			algorithmId = tpm2.HashAlgorithmSHA512
		default:
			return nil, errors.Errorf("Unsupported hash algorithm: %v", selected.Hash)
		}

		pcrSelectionList = append(pcrSelectionList, tpm2.PCRSelection{
			Hash:   algorithmId,
			Select: selected.Pcrs,
		})
	}

	return pcrSelectionList, nil
}
