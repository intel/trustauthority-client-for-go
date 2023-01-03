/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"encoding/base64"
	"fmt"
	"github.com/intel/amber/v1/client/tdx"
	"github.com/intel/amber/v1/client/tdx-cli/constants"
	"github.com/pkg/errors"
	"os"

	"github.com/spf13/cobra"
)

// quoteCmd represents the quote command
var quoteCmd = &cobra.Command{
	Use:   constants.QuoteCmd,
	Short: "Fetches the TD quote",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := getQuote(cmd)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return err
		}
		fmt.Fprintln(os.Stdout, token)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(quoteCmd)
	quoteCmd.Flags().StringP(constants.NonceOption, "n", "", "Nonce in base64 encoded format")
	quoteCmd.Flags().StringP(constants.UserDataOption, "u", "", "User Data in base64 encoded format")
}

func getQuote(cmd *cobra.Command) ([]byte, error) {

	userData, err := cmd.Flags().GetString(constants.UserDataOption)
	if err != nil {
		return nil, err
	}

	nonce, err := cmd.Flags().GetString(constants.NonceOption)
	if err != nil {
		return nil, err
	}

	var userDataBytes []byte
	if userData != "" {
		userDataBytes, err = base64.URLEncoding.DecodeString(userData)
		if err != nil {
			return nil, errors.Wrap(err, "Error while base64 decoding of userdata")
		}
	}

	var nonceBytes []byte
	if nonce != "" {
		nonceBytes, err = base64.URLEncoding.DecodeString(nonce)
		if err != nil {
			return nil, errors.Wrap(err, "Error while base64 decoding of nonce")
		}
	}

	evLogParser := tdx.NewEventLogParser()
	adapter, err := tdx.NewAdapter(userDataBytes, evLogParser)
	if err != nil {
		return nil, errors.Wrap(err, "Error while creating tdx adapter")
	}
	evidence, err := adapter.CollectEvidence(nonceBytes)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to collect evidence")
	}

	return evidence.Evidence, nil
}
