/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/intel/trustauthority-client/go-aztdx"
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/go-tdx"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// quoteCmd represents the quote command
var quoteCmd = &cobra.Command{
	Use:   constants.QuoteCmd,
	Short: "Fetches the TD quote",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := getQuote(cmd)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(quoteCmd)
	quoteCmd.Flags().StringP(constants.NonceOption, "n", "", "Nonce in base64 encoded format")
	quoteCmd.Flags().StringP(constants.UserDataOptions.Name, constants.UserDataOptions.ShortHand, "", constants.UserDataOptions.Description)
	quoteCmd.Flags().Bool(constants.WithAzTdxOption, false, "Collect Azure TDX evidence")
}

func getQuote(cmd *cobra.Command) error {

	userData, err := cmd.Flags().GetString(constants.UserDataOptions.Name)
	if err != nil {
		return err
	}

	nonce, err := cmd.Flags().GetString(constants.NonceOption)
	if err != nil {
		return err
	}

	withAzureTdx, err := cmd.Flags().GetBool(constants.WithAzTdxOption)
	if err != nil {
		return err
	}

	var userDataBytes []byte
	if userData != "" {
		userDataBytes, err = base64.StdEncoding.DecodeString(userData)
		if err != nil {
			return errors.Wrap(err, "Error while base64 decoding of userdata")
		}
	}

	var nonceBytes []byte
	if nonce != "" {
		nonceBytes, err = base64.StdEncoding.DecodeString(nonce)
		if err != nil {
			return errors.Wrap(err, "Error while base64 decoding of nonce")
		}
	}

	var adapter connector.EvidenceAdapter
	if withAzureTdx {
		adapter, err = aztdx.NewAzureTdxAdapter(userDataBytes)
	} else {
		adapter, err = tdx.NewTdxAdapter(userDataBytes, nil)
	}
	if err != nil {
		return errors.Wrap(err, "Error while creating tdx adapter")
	}

	evidence, err := adapter.CollectEvidence(nonceBytes)
	if err != nil {
		return errors.Wrap(err, "Failed to collect evidence")
	}

	fmt.Println("Quote:", base64.StdEncoding.EncodeToString(evidence.Evidence))
	if evidence.RuntimeData != nil {
		fmt.Println("runtime_data:", base64.StdEncoding.EncodeToString(evidence.RuntimeData))
	}
	if userData != "" {
		fmt.Println("user_data:", userData)
	}

	return nil
}
