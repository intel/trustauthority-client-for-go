/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/go-sevsnp"
	"github.com/intel/trustauthority-client/sevsnp-cli/constants"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// reportCmd represents the report command
var reportCmd = &cobra.Command{
	Use:   constants.ReportCmd,
	Short: "Fetches the SEVSNP report",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := getReport(cmd)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.Flags().StringP(constants.NonceOption, "n", "", "Nonce in base64 encoded format")
	reportCmd.Flags().StringP(constants.UserDataOption, "u", "", "User Data in base64 encoded format")
}

func getReport(cmd *cobra.Command) error {

	userData, err := cmd.Flags().GetString(constants.UserDataOption)
	if err != nil {
		return err
	}

	nonce, err := cmd.Flags().GetString(constants.NonceOption)
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
	var verifierNonce connector.VerifierNonce
	if nonce != "" {
		nonceBytes, err = base64.StdEncoding.DecodeString(nonce)
		if err != nil {
			return errors.Wrap(err, "Error while base64 decoding of nonce")
		}
		err = json.Unmarshal(nonceBytes, &verifierNonce)
		if err != nil {
			fmt.Println("Unmarshall error: ", err.Error())
		}
		nonceBytes = append(verifierNonce.Val, verifierNonce.Iat[:]...)
	}

	adapter, err := sevsnp.NewEvidenceAdapter(userDataBytes)
	if err != nil {
		return errors.Wrap(err, "Error while creating sevsnp adapter")
	}
	evidence, err := adapter.CollectEvidence(nonceBytes)
	if err != nil {
		return errors.Wrap(err, "Failed to collect sevsnp evidence")
	}

	fmt.Println("Report:", base64.StdEncoding.EncodeToString(evidence.Report))
	fmt.Println("runtime_data:", base64.StdEncoding.EncodeToString(evidence.RuntimeData))
	fmt.Println("user_data:", userData)

	return nil
}
