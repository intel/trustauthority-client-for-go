/*
 *   Copyright (c) 2022-2025 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"fmt"
	"os"

	"github.com/intel/trustauthority-client/go-tdx"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// createKeyPairCmd represents the create-key-pair command
var createKeyPairCmd = &cobra.Command{
	Use:   constants.CreateKeyPairCmd,
	Short: "Creates RSA3K keypair",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		return createKeyPair(cmd)
	},
}

func init() {
	rootCmd.AddCommand(createKeyPairCmd)
	createKeyPairCmd.Flags().StringP(constants.PublicKeyPathOption, "f", "", "File path to store public key")

	if err := createKeyPairCmd.MarkFlagRequired(constants.PublicKeyPathOption); err != nil {
		fmt.Fprintln(os.Stderr, "Error marking flag as required:", err)
	}
}

func createKeyPair(cmd *cobra.Command) error {

	publicKeyPath, err := cmd.Flags().GetString(constants.PublicKeyPathOption)
	if err != nil {
		return err
	}

	keyFilepath, err := ValidateFilePath(publicKeyPath)
	if err != nil {
		return errors.Wrap(err, "Invalid public key file path provided")
	}

	km := &tdx.KeyMetadata{
		KeyLength: constants.RSAKeyBitLength,
	}
	privateKeyPem, publicKeyPem, err := tdx.GenerateKeyPair(km)
	if err != nil {
		return err
	}
	defer tdx.ZeroizeByteArray(privateKeyPem)

	err = os.WriteFile(keyFilepath, publicKeyPem, 0640)
	if err != nil {
		return errors.Wrap(err, "I/O error while saving public key")
	}

	fmt.Println(string(privateKeyPem))
	return nil
}
