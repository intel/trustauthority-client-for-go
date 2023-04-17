/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"bytes"
	"github.com/intel/amber/v1/client/tdx-cli/constants"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
)

const (
	privateKeyPath = "privatekey.pem"
	publicKeyPath  = "publickey.pem"
)

func TestCreateKeyPairCmd(t *testing.T) {

	defer func() {
		os.Remove(privateKeyPath)
		os.Remove(publicKeyPath)
	}()

	tt := []struct {
		args        []string
		wantErr     bool
		description string
	}{
		{
			args: []string{
				constants.CreateKeyPairCmd,
			},
			wantErr:     false,
			description: "Test without inputs",
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

func execute(t *testing.T, c *cobra.Command, args ...string) (string, error) {
	t.Helper()

	buf := new(bytes.Buffer)
	c.SetOut(buf)
	c.SetErr(buf)
	c.SetArgs(args)

	err := c.Execute()
	return strings.TrimSpace(buf.String()), err
}
