/*
 *   Copyright (c) 2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   constants.VerifyCmd,
	Short: "Verify Trust Authority attestation token",
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
	verifyCmd.Flags().StringP(constants.ConfigOption, "c", "", "Trust Authority config in JSON format")
	verifyCmd.Flags().StringP(constants.TokenOption, "t", "", "Token in JWT format")
	verifyCmd.MarkFlagRequired(constants.TokenOption)
	verifyCmd.MarkFlagRequired(constants.ConfigOption)
}

func verifyToken(cmd *cobra.Command) error {

	configFile, err := cmd.Flags().GetString(constants.ConfigOption)
	if err != nil {
		return err
	}

	configFilePath, err := ValidateFilePath(configFile)
	if err != nil {
		return errors.Wrap(err, "Invalid config file path provided")
	}

	configJson, err := os.ReadFile(configFilePath)
	if err != nil {
		return errors.Wrapf(err, "Error reading config from file")
	}

	var config Config
	err = json.Unmarshal(configJson, &config)
	if err != nil {
		return errors.Wrap(err, "Error unmarshalling JSON from config")
	}

	if config.TrustAuthorityUrl == "" {
		return errors.New("Trust Authority URL is missing in config")
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	cfg := connector.Config{
		TlsCfg:  tlsConfig,
		BaseUrl: config.TrustAuthorityUrl,
	}

	trustAuthorityConnector, err := connector.New(&cfg)
	if err != nil {
		return err
	}

	token, err := cmd.Flags().GetString(constants.TokenOption)
	if err != nil {
		return err
	}

	parsedToken, err := trustAuthorityConnector.VerifyToken(string(token))
	if err != nil {
		return errors.Wrap(err, "Could not verify the token")
	}

	fmt.Fprintln(os.Stdout, parsedToken.Claims)
	return nil

}
