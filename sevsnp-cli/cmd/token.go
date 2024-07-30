/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/go-sevsnp"
	"github.com/intel/trustauthority-client/sevsnp-cli/constants"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// tokenCmd represents the token command
var tokenCmd = &cobra.Command{
	Use:   constants.TokenCmd,
	Short: "Fetches the attestation token from Trust Authority",
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

type Config struct {
	TrustAuthorityUrl    string `json:"trustauthority_url"`
	TrustAuthorityApiUrl string `json:"trustauthority_api_url"`
	TrustAuthorityApiKey string `json:"trustauthority_api_key"`
}

func init() {
	rootCmd.AddCommand(tokenCmd)
	tokenCmd.Flags().StringP(constants.ConfigOption, "c", "", "Trust Authority config in JSON format")
	tokenCmd.Flags().StringP(constants.UserDataOption, "u", "", "User Data in base64 encoded format")
	tokenCmd.Flags().StringP(constants.PolicyIdsOption, "p", "", "Trust Authority Policy Ids, comma separated")
	tokenCmd.Flags().StringP(constants.PublicKeyPathOption, "f", "", "Public key to be used as userdata")
	tokenCmd.Flags().StringP(constants.RequestIdOption, "r", "", "Request id to be associated with request")
	tokenCmd.Flags().StringP(constants.TokenAlgOption, "a", "", "Token signing algorithm to be used, support PS384 and RS256")
	tokenCmd.Flags().Bool(constants.PolicyMustMatchOption, false, "Enforce policies match during attestation")
	tokenCmd.MarkFlagRequired(constants.ConfigOption)
}

func getToken(cmd *cobra.Command) error {

	configFile, err := cmd.Flags().GetString(constants.ConfigOption)
	if err != nil {
		return err
	}

	configJson, err := os.ReadFile(configFile)
	if err != nil {
		return errors.Wrapf(err, "Error reading config from file")
	}

	var config Config
	err = json.Unmarshal(configJson, &config)
	if err != nil {
		return errors.Wrap(err, "Error unmarshalling JSON from config")
	}

	if config.TrustAuthorityApiUrl == "" || config.TrustAuthorityApiKey == "" {
		return errors.New("Either Trust Authority API URL or Trust Authority API Key is missing in config")
	}

	_, err = url.ParseRequestURI(config.TrustAuthorityApiUrl)
	if err != nil {
		return errors.Wrap(err, "Invalid Trust Authority API URL")
	}

	_, err = base64.URLEncoding.DecodeString(config.TrustAuthorityApiKey)
	if err != nil {
		return errors.Wrap(err, "Invalid Trust Authority Api key, must be base64 string")
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

	reqId, err := cmd.Flags().GetString(constants.RequestIdOption)
	if err != nil {
		return err
	}

	tokenSigningAlg, err := cmd.Flags().GetString(constants.TokenAlgOption)
	if err != nil {
		return err
	}

	policyMustMatch, err := cmd.Flags().GetBool(constants.PolicyMustMatchOption)
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

	if reqId != "" {
		requestIdRegex := regexp.MustCompile(`^[a-zA-Z0-9_ \/.-]{1,128}$`)
		if !requestIdRegex.Match([]byte(reqId)) {
			return errors.Errorf("Request ID should be atmost 128 characters long and should contain only alphanumeric characters, _, space, -, ., / or \\")
		}
	}

	if tokenSigningAlg != "" && !connector.ValidateTokenSigningAlg(tokenSigningAlg) {
		return errors.New("Token Signing Algorithm is unsupported, supported algorithms are PS384/RS256")
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	cfg := connector.Config{
		TlsCfg: tlsConfig,
		ApiUrl: config.TrustAuthorityApiUrl,
		ApiKey: config.TrustAuthorityApiKey,
	}

	trustAuthorityConnector, err := connector.New(&cfg)
	if err != nil {
		return err
	}

	adapter, err := sevsnp.NewEvidenceAdapter(userDataBytes)
	if err != nil {
		return errors.Wrap(err, "Error while creating sevsnp adapter")
	}

	response, err := trustAuthorityConnector.Attest(connector.AttestArgs{Adapter: adapter, PolicyIds: pIds, RequestId: reqId, TokenSigningAlg: tokenSigningAlg, PolicyMustMatch: policyMustMatch})
	if response.Headers != nil {
		fmt.Fprintln(os.Stderr, "Trace Id:", response.Headers.Get(connector.HeaderTraceId))
		if reqId != "" {
			fmt.Fprintln(os.Stderr, "Request Id:", response.Headers.Get(connector.HeaderRequestId))
		}
	}
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stdout, response.Token)
	return nil
}
