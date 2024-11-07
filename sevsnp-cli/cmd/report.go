/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/intel/trustauthority-client/go-sevsnp"
	"github.com/intel/trustauthority-client/sevsnp-cli/constants"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// ReportCmd represents the report command
var ReportCmd = &cobra.Command{
	Use:   constants.ReportCmd,
	Short: "Fetches the AMD SEVSNP report",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := getreport(cmd)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(ReportCmd)
	ReportCmd.Flags().StringP(constants.NonceOption, "n", "", "Nonce in base64 encoded format")
	ReportCmd.Flags().StringP(constants.UserDataOption, "u", "", "User Data in base64 encoded format")
	ReportCmd.Flags().Uint32P(constants.UserVmplOption, "v", 0, "User-provided VMPL for current VM running privilege, accepted values are: 0, 1, 2, 3")
}

func getreport(cmd *cobra.Command) error {

	userData, err := cmd.Flags().GetString(constants.UserDataOption)
	if err != nil {
		return err
	}

	nonce, err := cmd.Flags().GetString(constants.NonceOption)
	if err != nil {
		return err
	}

	userVmpl, err := cmd.Flags().GetUint32(constants.UserVmplOption)
	if err != nil {
		return err
	}
	if userVmpl > 3 {
		return errors.New("User-provided VMPL should be in the range of 0 to 3")
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

	adapter, err := sevsnp.NewEvidenceAdapter(userDataBytes, userVmpl)
	if err != nil {
		return errors.Wrap(err, "Error while creating sevsnp adapter")
	}
	evidence, err := adapter.CollectEvidence(nonceBytes)
	if err != nil {
		return errors.Wrap(err, "Failed to collect evidence")
	}

	fmt.Fprintln(os.Stdout, evidence.Evidence)
	return nil
}
