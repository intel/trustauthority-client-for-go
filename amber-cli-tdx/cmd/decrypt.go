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
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   constants.DecryptCmd,
	Short: "Decrypts the given base64 encoded encrypted blob",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := decrypt(cmd)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.Flags().StringP(constants.PrivateKeyPathOption, "k", "",
		"Private key file path")
	decryptCmd.Flags().StringP(constants.DecryptCmdInputOption, "i", "",
		"Base64 encoded encrypted blob")
	decryptCmd.Flags().StringP(constants.DecryptedDataFilePathOption, "o", "",
		"File path for saving decrypted data, if not specified decrypted data will be written to stdout")
	decryptCmd.MarkFlagRequired(constants.DecryptCmdInputOption)
	decryptCmd.MarkFlagRequired(constants.PrivateKeyPathOption)

}

func decrypt(cmd *cobra.Command) error {

	b64EncryptedData, err := cmd.Flags().GetString(constants.DecryptCmdInputOption)
	if err != nil {
		return err
	}

	encryptedData, err := base64.URLEncoding.DecodeString(b64EncryptedData)
	if err != nil {
		return errors.Wrap(err, "Error while base64 decoding of encrypted data")
	}

	privateKeyPath, err := cmd.Flags().GetString(constants.PrivateKeyPathOption)
	if err != nil {
		return err
	}

	em := tdx.EncryptionMetadata{
		PrivateKeyLocation: privateKeyPath,
	}
	decryptedData, err := tdx.Decrypt(encryptedData, &em)
	if err != nil {
		return err
	}

	decryptedDataPath, err := cmd.Flags().GetString(constants.DecryptedDataFilePathOption)
	if err != nil {
		return err
	}
	if decryptedDataPath == "" {
		fmt.Fprintln(os.Stdout, decryptedData)
	} else {
		err = ioutil.WriteFile(decryptedDataPath, decryptedData, 0600)
		if err != nil {
			return errors.Wrapf(err, "Error while writing data to file: %s", decryptedDataPath)
		}
	}

	return nil
}
