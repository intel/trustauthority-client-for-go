/*
 *   Copyright (c) 2022-2025 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/intel/trustauthority-client/go-tdx"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   constants.DecryptCmd,
	Short: "Decrypts the given base64 encoded encrypted blob",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		return decrypt(cmd)
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.Flags().StringP(constants.PrivateKeyPathOption, "f", "",
		"Private key file path")
	decryptCmd.Flags().String(constants.InputOption, "",
		"Base64 encoded encrypted blob")
	decryptCmd.Flags().StringP(constants.PrivateKeyOption, "k", "",
		"Private key to be used for decryption")
	if err := decryptCmd.MarkFlagRequired(constants.InputOption); err != nil {
		fmt.Fprintln(os.Stderr, "Error marking flag as required:", err)
	}
}

func decrypt(cmd *cobra.Command) error {

	privateKeyPath, err := cmd.Flags().GetString(constants.PrivateKeyPathOption)
	if err != nil {
		return err
	}

	b64PrivateKey, err := cmd.Flags().GetString(constants.PrivateKeyOption)
	if err != nil {
		return err
	}

	if privateKeyPath == "" && b64PrivateKey == "" {
		return errors.Errorf("One of the --%s or --%s are required", constants.PrivateKeyPathOption, constants.PrivateKeyOption)
	}

	keyFilepath, err := ValidateFilePath(privateKeyPath)
	if err != nil {
		return errors.Wrap(err, "Invalid private key file path provided")
	}

	b64EncryptedData, err := cmd.Flags().GetString(constants.InputOption)
	if err != nil {
		return err
	}

	encryptedData, err := base64.StdEncoding.DecodeString(b64EncryptedData)
	if err != nil {
		return errors.Wrap(err, "Error while base64 decoding of encrypted data")
	}

	privateKey, err := base64.StdEncoding.DecodeString(b64PrivateKey)
	if err != nil {
		return errors.Wrap(err, "Error while base64 decoding of private key")
	}
	defer tdx.ZeroizeByteArray(privateKey)

	em := tdx.EncryptionMetadata{
		PrivateKeyLocation: keyFilepath,
		PrivateKey:         privateKey,
		HashAlgorithm:      "SHA256",
	}
	decryptedData, err := tdx.Decrypt(encryptedData, &em)
	if err != nil {
		return err
	}
	defer tdx.ZeroizeByteArray(decryptedData)

	fmt.Fprintln(os.Stdout, decryptedData)
	return nil
}
