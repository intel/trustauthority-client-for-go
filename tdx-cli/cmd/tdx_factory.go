/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"strings"

	"github.com/intel/trustauthority-client/go-aztdx"
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/go-tdx"
	"github.com/intel/trustauthority-client/go-tpm"
)

// TdxAdapterFactory is an interface for creating TDX adapters.
type TdxAdapterFactory interface {
	New(cloudProvider string, eventLogDisabled bool) (connector.CompositeEvidenceAdapter, error)
}

// NewTdxAdapterFactory creates a new, default TDX adapter factory.
func NewTdxAdapterFactory(tpmFactory tpm.TpmFactory) TdxAdapterFactory {
	return &tdxAdapterFactory{
		tpmFactory: tpmFactory,
	}
}

type tdxAdapterFactory struct {
	tpmFactory tpm.TpmFactory // needed for Azure TDX adapter
}

func (f *tdxAdapterFactory) New(cloudProvider string, withCcel bool) (connector.CompositeEvidenceAdapter, error) {
	var tdxAdapter connector.CompositeEvidenceAdapter
	var err error
	if strings.ToLower(cloudProvider) == CloudProviderAzure {
		tdxAdapter, err = aztdx.NewCompositeEvidenceAdapter(f.tpmFactory)
	} else {
		tdxAdapter, err = tdx.NewCompositeEvidenceAdapter(withCcel)
	}

	if err != nil {
		return nil, err
	}

	return tdxAdapter, nil
}
