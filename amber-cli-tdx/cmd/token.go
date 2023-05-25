/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/intel/amber/v1/client"
	"github.com/intel/amber/v1/client/tdx"
	"github.com/intel/amber/v1/client/tdx-cli/constants"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// tokenCmd represents the token command
var tokenCmd = &cobra.Command{
	Use:   constants.TokenCmd,
	Short: "Fetches the attestation token from Amber",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := getToken(cmd)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(tokenCmd)
	tokenCmd.Flags().StringP(constants.UserDataOption, "u", "", "User Data in base64 encoded format")
	tokenCmd.Flags().StringP(constants.PolicyIdsOption, "p", "", "Amber Policy Ids, comma separated")
	tokenCmd.Flags().StringP(constants.PublicKeyPathOption, "f", "", "Public key to be used as userdata")
}

func getToken(cmd *cobra.Command) error {
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

	userData, err := cmd.Flags().GetString(constants.UserDataOption)
	if err != nil {
		return err
	}

	policyIds, err := cmd.Flags().GetString(constants.PolicyIdsOption)
	if err != nil {
		return err
	}

	publicKeyPath, err := cmd.Flags().GetString(constants.PublicKeyPathOption)
	if err != nil {
		return err
	}

	var userDataBytes []byte
	if userData != "" {
		userDataBytes, err = base64.StdEncoding.DecodeString(userData)
		if err != nil {
			return errors.Wrap(err, "Error while base64 decoding of userdata")
		}
	} else if publicKeyPath != "" {
		publicKey, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return errors.Wrap(err, "Error reading public key from file")
		}

		publicKeyBlock, _ := pem.Decode(publicKey)
		if publicKeyBlock == nil {
			return errors.Errorf("No PEM data found in public key file")
		}
		userDataBytes = publicKeyBlock.Bytes
	}

	var pIds []uuid.UUID
	if len(policyIds) != 0 {
		Ids := strings.Split(policyIds, ",")
		for _, id := range Ids {
			if uid, err := uuid.Parse(id); err != nil {
				return errors.Errorf("Policy Id:%s is not a valid UUID", id)
			} else {
				pIds = append(pIds, uid)
			}
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

	// evLogParser := tdx.NewEventLogParser()
	adapter, err := tdx.NewAzureAdapter(userDataBytes, nil)
	if err != nil {
		return errors.Wrap(err, "Error while creating tdx adapter")
	}

	token, err := amberClient.CollectToken(adapter, pIds)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stdout, token)
	return nil
}
