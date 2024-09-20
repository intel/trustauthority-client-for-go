/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"fmt"
	"os"

	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   constants.RootCmd,
	Short: constants.CLIShortDescription,
	Long:  ``,
}

// simpleFormatter is a logrus formatter that logs message without level, time, etc.
type simpleFormatter struct{}

func (f *simpleFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(fmt.Sprintf("%s\n", entry.Message)), nil
}

func init() {
	logrus.SetFormatter(&simpleFormatter{})

	rootCmd.AddCommand(newEvidenceCommand())
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
