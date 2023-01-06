/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"fmt"
	"github.com/intel/amber/v1/client/tdx-cli/constants"
	"github.com/spf13/cobra"
	"os"
)

var Version = ""
var GitHash = ""
var BuildDate = ""

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   constants.VersionCmd,
	Short: "Version details of Amber Attestation Client for TDX",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := getVersion()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func getVersion() error {
	verStr := fmt.Sprintf("CLI Name: %s\n", constants.CLIShortDescription)
	verStr = verStr + fmt.Sprintf("Version: %s-%s\n", Version, GitHash)
	verStr = verStr + fmt.Sprintf("Build Date: %s\n", BuildDate)
	fmt.Fprintln(os.Stdout, verStr)
	return nil
}
