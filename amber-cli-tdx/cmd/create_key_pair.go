/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/intel/amber/v1/client/tdx"
	"github.com/intel/amber/v1/client/tdx-cli/constants"
	"github.com/intel/amber/v1/client/tdx-cli/utils"
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
}

func createKeyPair(cmd *cobra.Command) error {

	privateKeyPem, publicKeyPem, err := utils.GenerateKeyPair()
	if err != nil {
		return err
	}
	defer tdx.ZeroizeByteArray(privateKeyPem)

	err = ioutil.WriteFile(constants.PublicKeyFileName, publicKeyPem, 0644)
	if err != nil {
		return errors.Wrapf(err, "I/O error while saving public key at %s", constants.PublicKeyFileName)
	}

	fmt.Println(string(privateKeyPem))
	return nil
}
