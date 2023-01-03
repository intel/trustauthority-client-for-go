/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"fmt"
	"github.com/intel/amber/v1/client/tdx-cli/constants"
	"github.com/intel/amber/v1/client/tdx-cli/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
)

// createKeyPairCmd represents the create-key-pair command
var createKeyPairCmd = &cobra.Command{
	Use:   constants.CreateKeyPairCmd,
	Short: "Creates RSA3K keypair",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := createKeyPair(cmd)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(createKeyPairCmd)
	createKeyPairCmd.Flags().StringP(constants.PrivateKeyPathOption, "k", "",
		"File path to store private key")
	createKeyPairCmd.MarkFlagRequired(constants.PrivateKeyPathOption)
}

func createKeyPair(cmd *cobra.Command) error {

	privateKeyPem, publicKeyPem, err := utils.GenerateKeyPair()
	if err != nil {
		return err
	}

	privateKeyPath, err := cmd.Flags().GetString(constants.PrivateKeyPathOption)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(privateKeyPath, privateKeyPem, 0600)
	if err != nil {
		return errors.Wrap(err, "I/O error while saving private key")
	}

	err = ioutil.WriteFile(constants.PublicKeyFileName, publicKeyPem, 0644)
	if err != nil {
		return errors.Wrapf(err, "I/O error while saving public key at %s", constants.PublicKeyFileName)
	}

	return nil
}
