/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"fmt"
	"os"

	"github.com/intel/amber/v1/client/tdx"
	"github.com/intel/amber/v1/client/tdx-cli/constants"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
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
	createKeyPairCmd.Flags().StringP(constants.PublicKeyPathOption, "f", "", "File path to store public key")
	createKeyPairCmd.MarkFlagRequired(constants.PublicKeyPathOption)
}

func createKeyPair(cmd *cobra.Command) error {

	publicKeyPath, err := cmd.Flags().GetString(constants.PublicKeyPathOption)
	if err != nil {
		return err
	}

	km := &tdx.KeyMetadata{
		KeyLength: constants.RSAKeyBitLength,
	}
	privateKeyPem, publicKeyPem, err := tdx.GenerateKeyPair(km)
	if err != nil {
		return err
	}
	defer tdx.ZeroizeByteArray(privateKeyPem)

	err = os.WriteFile(publicKeyPath, publicKeyPem, 0644)
	if err != nil {
		return errors.Wrap(err, "I/O error while saving public key")
	}

	fmt.Println(string(privateKeyPem))
	return nil
}
