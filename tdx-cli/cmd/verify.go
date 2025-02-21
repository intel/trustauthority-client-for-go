/*
 *   Copyright (c) 2023-2025 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func newVerifyCommand(cfgFactory ConfigFactory, ctrFactory connector.ConnectorFactory) *cobra.Command {
	verifyCmd := &cobra.Command{
		Use:   constants.VerifyCmd,
		Short: "Verify Trust Authority attestation token",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := verifyToken(cmd, cfgFactory, ctrFactory)
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				return err
			}

			return nil
		},
	}
	verifyCmd.Flags().StringP(constants.ConfigOptions.Name, constants.ConfigOptions.ShortHand, "", constants.ConfigOptions.Description)
	verifyCmd.Flags().StringP(constants.TokenOption, "t", "", "Token in JWT format")
	verifyCmd.MarkFlagRequired(constants.TokenOption)
	verifyCmd.MarkFlagRequired(constants.ConfigOptions.Name)

	return verifyCmd
}

func verifyToken(cmd *cobra.Command, cfgFactory ConfigFactory, ctrFactory connector.ConnectorFactory) error {

	configFile, err := cmd.Flags().GetString(constants.ConfigOptions.Name)
	if err != nil {
		return err
	}

	config, err := cfgFactory.LoadConfig(configFile)
	if err != nil {
		return errors.Wrapf(err, "Could not read config file %q", configFile)
	}

	if config.TrustAuthorityUrl == "" {
		return errors.New("Trust Authority URL is missing in config")
	}

	tlsConfig := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	cfg := connector.Config{
		TlsCfg:  tlsConfig,
		BaseUrl: config.TrustAuthorityUrl,
	}

	trustAuthorityConnector, err := ctrFactory.NewConnector(&cfg)
	if err != nil {
		return err
	}

	token, err := cmd.Flags().GetString(constants.TokenOption)
	if err != nil {
		return err
	}

	parsedToken, err := trustAuthorityConnector.VerifyToken(string(token))
	if err != nil {
		return errors.Wrap(err, "Could not verify attestation token")
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		fmt.Println("Token is valid and issued by Intel Trust Authority hosted at ", claims["iss"])
	} else {
		return errors.New("Invalid JWT Token")
	}
	return nil

}
