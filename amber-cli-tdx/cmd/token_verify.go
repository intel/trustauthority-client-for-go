/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"

	"github.com/intel/amber/v1/client"
	"github.com/intel/amber/v1/client/tdx-cli/constants"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// verifyCmd represents the token command
var verifyCmd = &cobra.Command{
	Use:   constants.VerifyCmd,
	Short: "Verify the amber token",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := verifyToken(cmd)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().StringP(constants.VerifyTokenOption, "f", "", "Path to token file")
}

func verifyToken(cmd *cobra.Command) error {
	var err error

	viper.AutomaticEnv()
	amberUrl := viper.GetString(constants.AmberUrlEnv)
	if amberUrl == "" {
		return errors.Errorf("%s is not set in env", constants.AmberUrlEnv)
	} else {
		_, err = url.ParseRequestURI(amberUrl)
		if err != nil {
			return errors.Wrap(err, "Invalid Amber URL")
		}
	}

	amberApikey := viper.GetString(constants.AmberApiKeyEnv)
	if amberApikey == "" {
		return errors.Errorf("%s is not set in env", constants.AmberApiKeyEnv)
	} else {
		_, err = base64.URLEncoding.DecodeString(amberApikey)
		if err != nil {
			return errors.Wrap(err, "Invalid Api key, must be base64 string")
		}
	}

	tokenPath, err := cmd.Flags().GetString(constants.VerifyTokenOption)
	if err != nil {
		return err
	}

	var token []byte
	if tokenPath != "" {
		token, err = os.ReadFile(tokenPath)
		if err != nil {
			return errors.Wrap(err, "Error reading token from file")
		}

	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	cfg := client.Config{
		Url:    amberUrl,
		TlsCfg: tlsConfig,
		ApiKey: amberApikey,
	}

	amberClient, err := client.New(&cfg)
	if err != nil {
		return err
	}

	status, err := amberClient.VerifyToken(string(token))
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stdout, status)
	return nil
}
