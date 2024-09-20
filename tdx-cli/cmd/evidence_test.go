/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package cmd

import (
	"os"
	"testing"

	"github.com/intel/trustauthority-client/tdx-cli/constants"
)

func TestEvidence(t *testing.T) {
	// This is an interim solution to get sufficient (80%) test coverage for the tdx-cli.
	// A "proper" solution is needed in which external dependencies (adapters, connectors, factories,
	// etc.) are mocked (see CASSINI-23218).
	//
	// It essentailly brute forces the evidence command, setting up a temporary config file, using the
	// mock AzTdx adapter (via build flags and "cloud_provider" is azure in the config file) and
	// setting the --no-verifier-nonce flag.
	configJson := `{
		"trustauthority_api_url": "https://example.com",
		"trustauthority_api_key": "YXBpa2V5",
		"cloud_provider": "azure"
	}`
	_ = os.WriteFile(confFilePath, []byte(configJson), 0600)
	defer os.Remove(confFilePath)

	cmd := newEvidenceCommand()
	cmd.SetArgs([]string{
		constants.EvidenceCmd,
		"--" + constants.ConfigOption,
		confFilePath,
		"--" + constants.NoVerifierNonceOption,
		"--" + constants.WithTdxOption,
	})

	err := cmd.Execute()
	if err != nil {
		t.Errorf("Error executing command: %v", err)
	}
}
