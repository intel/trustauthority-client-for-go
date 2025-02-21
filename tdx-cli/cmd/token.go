/*
 *   Copyright (c) 2022-2024 Intel Corporation
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
	"regexp"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/go-nvgpu"
	"github.com/intel/trustauthority-client/go-tpm"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const (
	CloudProviderAzure = "azure"
)

var (
	// max length of file name to be allowed is 255 bytes and characters allowed are a-z, A-Z, 0-9, _, ., -
	fileNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_. -]{1,255}$`)
	// in file path, characters allowed are a-z, A-Z, 0-9, _, ., -, \, /, :
	filePathRegex = regexp.MustCompile(`^[a-zA-Z0-9_. :/\\-]*$`)
)

func newTokenCommand(tdxAdapterFactory TdxAdapterFactory,
	tpmAdapterFactory tpm.TpmAdapterFactory,
	cfgFactory ConfigFactory,
	ctrFactory connector.ConnectorFactory) *cobra.Command {

	tokenCmd := cobra.Command{
		Use:   constants.TokenCmd,
		Short: "Fetches the attestation token from Trust Authority",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := getToken(cmd, tdxAdapterFactory, tpmAdapterFactory, cfgFactory, ctrFactory)
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				return err
			}
			return nil
		},
	}

	tokenCmd.Flags().StringP(constants.ConfigOptions.Name, constants.ConfigOptions.ShortHand, "", constants.ConfigOptions.Description)
	tokenCmd.Flags().StringP(constants.UserDataOptions.Name, constants.UserDataOptions.ShortHand, "", constants.UserDataOptions.Description)
	tokenCmd.Flags().StringP(constants.PolicyIdsOptions.Name, constants.PolicyIdsOptions.ShortHand, "", constants.PolicyIdsOptions.Description)
	tokenCmd.Flags().StringP(constants.PublicKeyPathOption, "f", "", "Public key to be used as userdata")
	tokenCmd.Flags().StringP(constants.RequestIdOptions.Name, constants.RequestIdOptions.ShortHand, "", constants.RequestIdOptions.Description)
	tokenCmd.Flags().StringP(constants.TokenAlgOptions.Name, constants.TokenAlgOptions.ShortHand, "", constants.TokenAlgOptions.Description)
	tokenCmd.Flags().Bool(constants.PolicyMustMatchOptions.Name, false, constants.PolicyMustMatchOptions.Description)
	tokenCmd.Flags().Bool(constants.WithTdxOptions.Name, false, constants.WithTdxOptions.Description)
	tokenCmd.Flags().Bool(constants.WithTpmOptions.Name, false, constants.WithTpmOptions.Description)
	tokenCmd.Flags().Bool(constants.WithNvGpuOptions.Name, false, constants.WithNvGpuOptions.Description)
	tokenCmd.Flags().Bool(constants.NoVerifierNonceOptions.Name, false, constants.NoVerifierNonceOptions.Description)
	tokenCmd.Flags().Bool(constants.WithImaLogsOptions.Name, false, constants.WithImaLogsOptions.Description)
	tokenCmd.Flags().Bool(constants.WithEventLogsOptions.Name, false, constants.WithEventLogsOptions.Description)
	tokenCmd.Flags().Bool(constants.WithCcelOptions.Name, false, constants.WithCcelOptions.Description)

	tokenCmd.MarkFlagRequired(constants.ConfigOptions.Name)
	return &tokenCmd
}

func getToken(cmd *cobra.Command,
	tdxAdapterFactory TdxAdapterFactory,
	tpmAdapterFactory tpm.TpmAdapterFactory,
	cfgFactory ConfigFactory,
	ctrFactory connector.ConnectorFactory) error {

	var builderOptions []connector.EvidenceBuilderOption

	configFile, err := cmd.Flags().GetString(constants.ConfigOptions.Name)
	if err != nil {
		return err
	}
	config, err := cfgFactory.LoadConfig(configFile)
	if err != nil {
		return errors.Wrapf(err, "Could not read config file %q", configFile)
	}

	// token requires Trust Authority API URL and API key
	if config.TrustAuthorityApiUrl == "" || config.TrustAuthorityApiKey == "" {
		return errors.New("Either Trust Authority API URL or Trust Authority API Key is missing in config")
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
		TlsCfg: tlsConfig,
		ApiUrl: config.TrustAuthorityApiUrl,
		ApiKey: config.TrustAuthorityApiKey,
	}

	trustAuthorityConnector, err := ctrFactory.NewConnector(&cfg)
	if err != nil {
		return err
	}

	_, err = base64.URLEncoding.DecodeString(config.TrustAuthorityApiKey)
	if err != nil {
		// check if jwt token is passed instead of api-key (packaged software use-case)
		_, _, err = new(jwt.Parser).ParseUnverified(config.TrustAuthorityApiKey, jwt.MapClaims{})
		if err != nil {
			return errors.Wrap(err, "Invalid Trust Authority Api key")
		}
	}

	userData, err := cmd.Flags().GetString(constants.UserDataOptions.Name)
	if err != nil {
		return err
	}

	policyIds, err := cmd.Flags().GetString(constants.PolicyIdsOptions.Name)
	if err != nil {
		return err
	}

	publicKeyPath, err := cmd.Flags().GetString(constants.PublicKeyPathOption)
	if err != nil {
		return err
	}

	reqId, err := cmd.Flags().GetString(constants.RequestIdOptions.Name)
	if err != nil {
		return err
	}

	tokenSigningAlg, err := cmd.Flags().GetString(constants.TokenAlgOptions.Name)
	if err != nil {
		return err
	}

	noVerifierNonce, err := cmd.Flags().GetBool(constants.NoVerifierNonceOptions.Name)
	if err != nil {
		return err
	}

	if !noVerifierNonce {
		builderOptions = append(builderOptions, connector.WithVerifierNonce(trustAuthorityConnector))
	}

	policyMustMatch, err := cmd.Flags().GetBool(constants.PolicyMustMatchOptions.Name)
	if err != nil {
		return err
	}
	builderOptions = append(builderOptions, connector.WithPoliciesMustMatch(policyMustMatch))

	withTdx, err := cmd.Flags().GetBool(constants.WithTdxOptions.Name)
	if err != nil {
		return err
	}

	withTpm, err := cmd.Flags().GetBool(constants.WithTpmOptions.Name)
	if err != nil {
		return err
	}

	withNvGpu, err := cmd.Flags().GetBool(constants.WithNvGpuOptions.Name)
	if err != nil {
		return err
	}

	withImaLogs, err := cmd.Flags().GetBool(constants.WithImaLogsOptions.Name)
	if err != nil {
		return err
	}

	withCcel, err := cmd.Flags().GetBool(constants.WithCcelOptions.Name)
	if err != nil {
		return err
	}

	withUefiEventLogs, err := cmd.Flags().GetBool(constants.WithEventLogsOptions.Name)
	if err != nil {
		return err
	}

	// backward compatibility cli options: if the user did not specify "--tdx, "--tpm" or "--nvgpu" options,
	// include TDX evidence by default
	if !withTdx && !withTpm && !withNvGpu {
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
			return errors.New("No PEM data found in public key file")
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
			return errors.New("Request ID should be atmost 128 characters long and should contain only alphanumeric characters, _, space, -, ., / or \\")
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
		tdxAdapter, err := tdxAdapterFactory.New(config.CloudProvider, withCcel)
		if err != nil {
			return errors.Wrap(err, "Error creating tdx adapter")
		}

		builderOptions = append(builderOptions, connector.WithEvidenceAdapter(tdxAdapter))
	}

	if withTpm {
		if config.Tpm == nil {
			return errors.Errorf("TPM configuration not found in config file %q", configFile)
		}

		tpmOptions := []tpm.TpmAdapterOptions{
			tpm.WithOwnerAuth(config.Tpm.OwnerAuth),
			tpm.WithAkHandle(int(config.Tpm.AkHandle)),
			tpm.WithPcrSelections(config.Tpm.PcrSelections),
			tpm.WithAkCertificateUri(config.Tpm.AkCertificateUri),
			tpm.WithImaLogs(withImaLogs),
			tpm.WithUefiEventLogs(withUefiEventLogs),
		}

		tpmAdapter, err := tpmAdapterFactory.New(tpmOptions...)
		if err != nil {
			return errors.Wrap(err, "Error while creating tpm adapter")
		}

		builderOptions = append(builderOptions, connector.WithEvidenceAdapter(tpmAdapter))
	}

	if withNvGpu {
		gpuAdapter := nvgpu.NewCompositeEvidenceAdapter()
		builderOptions = append(builderOptions, connector.WithEvidenceAdapter(gpuAdapter))
	}

	evidenceBuilder, err := connector.NewEvidenceBuilder(builderOptions...)
	if err != nil {
		return err
	}

	evidence, err := evidenceBuilder.Build()
	if err != nil {
		return err
	}

	response, err := trustAuthorityConnector.AttestEvidence(evidence, config.CloudProvider, reqId)
	if response.Headers != nil {
		fmt.Fprintln(os.Stderr, "Trace Id:", response.Headers.Get(connector.HeaderTraceId))
		if reqId != "" {
			fmt.Fprintln(os.Stderr, "Request Id:", response.Headers.Get(connector.HeaderRequestId))
		}
	}
	if err != nil {
		return err
	}

	fmt.Fprint(os.Stdout, response.Token)
	return nil
}
