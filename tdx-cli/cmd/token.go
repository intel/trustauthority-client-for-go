/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/google/uuid"
	"github.com/intel/trustauthority-client/aztdx"
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/intel/trustauthority-client/tpm"
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

var (
	// max length of file name to be allowed is 255 bytes and characters allowed are a-z, A-Z, 0-9, _, ., -
	fileNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_. -]{1,255}$`)
	// in file path, characters allowed are a-z, A-Z, 0-9, _, ., -, \, /, :
	filePathRegex = regexp.MustCompile(`^[a-zA-Z0-9_. :/\\-]*$`)
)

type Config struct {
	TrustAuthorityUrl    string     `json:"trustauthority_url"`
	TrustAuthorityApiUrl string     `json:"trustauthority_api_url"`
	TrustAuthorityApiKey string     `json:"trustauthority_api_key"`
	Tpm                  *TpmConfig `json:"tpm,omitempty"`
}

type TpmConfig struct {
	// AkHandle is the handle of the TPM key that will be used to sign TPM quotes
	AkHandle HexInt `json:"ak_handle"`
	// EkHandle is needed during AK provisioning to create the AK
	EkHandle HexInt `json:"ek_handle"`
	// OwnerAuth is the owner password of the TPM (defaults to "")
	OwnerAuth string `json:"owner_auth"`
	// PcrSelections is the list of PCR banks and indices that are included in TPM quotes
	PcrSelections string `json:"pcr_selections"`
	// AkCertificateUri is the URI of the AK certificate.  Currently, "file://{full path}" and
	// "nvram://{index in hex}" are supported.
	AkCertificateUri string `json:"ak_certificate"`
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
	tokenCmd.Flags().Bool(constants.NoEventLogOption, true, "Do not collect Event Log")
	tokenCmd.Flags().Bool(constants.WithTdxOption, false, "Include TDX evidence")
	tokenCmd.Flags().Bool(constants.WithTpmOption, false, "Include TPM evidence")
	tokenCmd.Flags().Bool(constants.NoVerifierNonceOption, false, "Do not include an ITA verifier-nonce in evidence")

	tokenCmd.MarkFlagRequired(constants.ConfigOption)
}

func getToken(cmd *cobra.Command) error {
	var builderOptions []connector.EvidenceBuilderOption

	configFile, err := cmd.Flags().GetString(constants.ConfigOption)
	if err != nil {
		return err
	}
	config, err := loadConfig(configFile)
	if err != nil {
		return err
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

	noVerifierNonce, err := cmd.Flags().GetBool(constants.NoVerifierNonceOption)
	if err != nil {
		return err
	}

	if !noVerifierNonce {
		builderOptions = append(builderOptions, connector.WithVerifierNonce(trustAuthorityConnector))
	}

	policyMustMatch, err := cmd.Flags().GetBool(constants.PolicyMustMatchOption)
	if err != nil {
		return err
	}
	builderOptions = append(builderOptions, connector.WithPolicyMustMatch(policyMustMatch))

	withTdx, err := cmd.Flags().GetBool(constants.WithTdxOption)
	if err != nil {
		return err
	}

	withTpm, err := cmd.Flags().GetBool(constants.WithTpmOption)
	if err != nil {
		return err
	}

	// backward compatibility cli options: if the user did not specify "--tdx" or "--tpm" options,
	// include TDX evidence by default
	if !withTdx && !withTpm {
		withTdx = true
	}

	var userDataBytes []byte
	if userData != "" {
		userDataBytes, err = base64.StdEncoding.DecodeString(userData)
		if err != nil {
			return errors.Wrap(err, "Error while base64 decoding of userdata")
		}
	} else if publicKeyPath != "" {
		keyFilepath, err := ValidateFilePath(publicKeyPath)
		if err != nil {
			return errors.Wrap(err, "Invalid public key file path provided")
		}
		publicKey, err := os.ReadFile(keyFilepath)
		if err != nil {
			return errors.Wrap(err, "Error reading public key from file")
		}

		publicKeyBlock, _ := pem.Decode(publicKey)
		if publicKeyBlock == nil {
			return errors.Errorf("No PEM data found in public key file")
		}
		userDataBytes = publicKeyBlock.Bytes
	}
	if len(userDataBytes) != 0 {
		builderOptions = append(builderOptions, connector.WithUserData(userDataBytes))
	}

	pIds, err := parsePolicyIds(policyIds)
	if err != nil {
		return err
	}
	if len(pIds) != 0 {
		builderOptions = append(builderOptions, connector.WithPolicyIds(pIds))
	}

	if reqId != "" {
		requestIdRegex := regexp.MustCompile(`^[a-zA-Z0-9_ \/.-]{1,128}$`)
		if !requestIdRegex.Match([]byte(reqId)) {
			return errors.Errorf("Request ID should be atmost 128 characters long and should contain only alphanumeric characters, _, space, -, ., / or \\")
		}
	} else {
		reqId = uuid.New().String()
	}

	if tokenSigningAlg != "" {
		if !connector.ValidateTokenSigningAlg(tokenSigningAlg) {
			return errors.Errorf("%q is not a valid token signing algorithm", tokenSigningAlg)
		}

		signingAlg := connector.JwtAlg(tokenSigningAlg)
		builderOptions = append(builderOptions, connector.WithTokenSigningAlgorithm(signingAlg))
	}

	if withTdx {
		tdxAdapter, err := aztdx.NewAzureTdxAdapter()
		if err != nil {
			return errors.Wrap(err, "Error while creating tdx adapter")
		}

		builderOptions = append(builderOptions, connector.WithEvidenceAdapter(tdxAdapter))
	}

	if withTpm {
		if config.Tpm == nil {
			return errors.Errorf("TPM configuration not found in config file %q", configFile)
		}

		tpmOptions := []tpm.TpmAdapterOptions{
			tpm.WithAkHandle(int(config.Tpm.AkHandle)),
			tpm.WithOwnerAuth(config.Tpm.OwnerAuth),
			tpm.WithPcrSelections(config.Tpm.PcrSelections),
			tpm.WithAkCertificateUri(config.Tpm.AkCertificateUri),
		}

		tpmAdapter, err := tpm.NewEvidenceAdapterWithOptions(tpmOptions...)
		if err != nil {
			return err
		}

		builderOptions = append(builderOptions, connector.WithEvidenceAdapter(tpmAdapter))
	}

	evidenceBuilder, err := connector.NewEvidenceBuilder(builderOptions...)
	if err != nil {
		return err
	}

	evidence, err := evidenceBuilder.Build()
	if err != nil {
		return err
	}

	response, err := trustAuthorityConnector.AttestEvidence(evidence, reqId)
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

func ValidateFilePath(path string) (string, error) {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return "", errors.New("path cannot be directory, please provide file path")
	}
	cleanedPath := filepath.Clean(path)
	if err := checkFilePathForInvalidChars(cleanedPath); err != nil {
		return "", err
	}
	r, err := filepath.EvalSymlinks(cleanedPath)
	if err != nil && !os.IsNotExist(err) {
		return cleanedPath, errors.New("Unsafe symlink detected in path")
	}
	if r == "" {
		return cleanedPath, nil
	}
	if err = checkFilePathForInvalidChars(r); err != nil {
		return "", err
	}
	return r, nil
}

func checkFilePathForInvalidChars(path string) error {
	filePath, fileName := filepath.Split(path)
	//Max file path length allowed in linux is 4096 characters
	if len(path) > constants.LinuxFilePathSize || !filePathRegex.MatchString(filePath) {
		return errors.New("Invalid file path provided")
	}
	if !fileNameRegex.MatchString(fileName) {
		return errors.New("Invalid file name provided")
	}
	return nil
}
