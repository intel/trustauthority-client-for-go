/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"github.com/intel/amber/v1/client"
	"github.com/intel/amber/v1/client/tdx"
	"github.com/intel/amber/v1/client/tdx-cli/constants"
	"io/ioutil"
	"net/url"
	"os"
	"strings"

	"github.com/google/uuid"
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
	tokenCmd.Flags().StringP(constants.PolicyIdsOption, "p", "",
		"Amber Policy Ids, comma separated")
	tokenCmd.Flags().
		Bool(constants.TLSVerifyOption, true, "Verify tls certificates when making connection to amber")
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
		if len(amberApikey) > constants.MaxKeyLen || !constants.HexReg.MatchString(amberApikey) {
			return errors.New("Invalid Api key")
		}
	}

	policyIds, err := cmd.Flags().GetString(constants.PolicyIdsOption)
	if err != nil {
		return err
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

	tlsVerify, err := cmd.Flags().GetBool(constants.TLSVerifyOption)
	if err != nil {
		return err
	}
	var tlsConfig *tls.Config

	if tlsVerify {
		tlsConfig = &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: false,
		}
	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
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

	publicKey, err := ioutil.ReadFile(constants.PublicKeyFileName)
	if err != nil {
		return errors.Wrap(err, "Error reading public key from file")
	}

	publicKeyBlock, _ := pem.Decode(publicKey)

	evLogParser := tdx.NewEventLogParser()
	adapter, err := tdx.NewAdapter(publicKeyBlock.Bytes, evLogParser)
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
