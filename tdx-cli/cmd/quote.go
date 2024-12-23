/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"fmt"

	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/spf13/cobra"
)

// quoteCmd represents the quote command
var quoteCmd = &cobra.Command{
	Use:   constants.QuoteCmd,
	Short: "Deprecated (see 'evidence' command): Fetches the TD quote",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("The quote command is deprecated (see 'evidence' command)")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(quoteCmd)
}
