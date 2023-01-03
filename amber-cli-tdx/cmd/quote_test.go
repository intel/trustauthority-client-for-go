/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"github.com/intel/amber/v1/client/tdx-cli/constants"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestQuoteCmd(t *testing.T) {

	tt := []struct {
		args        []string
		wantErr     bool
		description string
	}{
		{
			args:    []string{constants.QuoteCmd, "--" + constants.UserDataOption, "dGVzdHVzZXJkYXRh"},
			wantErr: false,
			description: "Test with valid inputs with providing value for " + constants.
				UserDataOption + " option",
		},
		{
			args:    []string{constants.QuoteCmd},
			wantErr: false,
			description: "Test with valid inputs without providing value for " + constants.
				UserDataOption + " option",
		},
		{
			args: []string{constants.QuoteCmd, "--" + constants.UserDataOption, "dGVzdHVzZXJkYXRh",
				"--" + constants.NonceOption, "dGVzdHVzZXJkYXRh"},
			wantErr: false,
			description: "Test with all valid inputs with providing value for " + constants.
				UserDataOption + " " + constants.NonceOption + " options",
		},
	}

	for _, tc := range tt {
		_, err := execute(t, rootCmd, tc.args...)

		if tc.wantErr == true {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}
