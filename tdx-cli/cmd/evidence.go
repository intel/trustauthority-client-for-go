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
	"fmt"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/go-nvgpu"
	"github.com/intel/trustauthority-client/go-tpm"
	"github.com/intel/trustauthority-client/tdx-cli/constants"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func newEvidenceCommand(tdxAdapterFactory TdxAdapterFactory,
	tpmAdapterFactory tpm.TpmAdapterFactory,
	cfgFactory ConfigFactory,
	ctrFactory connector.ConnectorFactory) *cobra.Command {

	var withTpm bool
	var withTdx bool
	var withNvGpu bool
	var tokenSigningAlg string
	var noVerifierNonce bool
	var configPath string
	var policiesMustMatch bool
	var userData string
	var policyIds string
	var withImaLogs bool
	var withEventLogs bool
	var withCcel bool
	var builderOptions []connector.EvidenceBuilderOption
	var ctr connector.Connector

	cmd := cobra.Command{
		Use:   constants.EvidenceCmd,
		Short: "Collects evidence from the underlying host and displays it in json format",
		Long: `Use this command to output evidence in json format.  The json can be used 
 as the body of a request to the Trust Authority's /appraisal/v2/attest endpoint.
 Multiple attestation types can be combined in the output using the --tpm and --tdx
 options.`,
		RunE: func(cmd *cobra.Command, args []string) error {

			cfg, err := cfgFactory.LoadConfig(configPath)
			if err != nil {
				return errors.Wrapf(err, "Could not read config file %q", configPath)
			}

			var userDataBytes []byte
			if userData != "" {
				userDataBytes, err = base64.StdEncoding.DecodeString(userData)
				if err != nil {
					return errors.Wrap(err, "Error while base64 decoding of userdata")
				}
			}
			if len(userDataBytes) != 0 {
				builderOptions = append(builderOptions, connector.WithUserData(userDataBytes))
			}

			policyIds, err := parsePolicyIds(policyIds)
			if err != nil {
				return err
			}

			if policyIds != nil {
				builderOptions = append(builderOptions, connector.WithPolicyIds(policyIds))
			}

			if policiesMustMatch {
				builderOptions = append(builderOptions, connector.WithPoliciesMustMatch(policiesMustMatch))
			}

			// default to tdx if no evidence types are provided
			if !withTdx && !withTpm && !withNvGpu {
				withTdx = true
			}

			if withTpm {
				if cfg.Tpm == nil {
					return errors.Errorf("TPM configuration not found in config file %q", configPath)
				}

				tpmOptions := []tpm.TpmAdapterOptions{
					tpm.WithOwnerAuth(cfg.Tpm.OwnerAuth),
					tpm.WithAkHandle(int(cfg.Tpm.AkHandle)),
					tpm.WithPcrSelections(cfg.Tpm.PcrSelections),
					tpm.WithAkCertificateUri(cfg.Tpm.AkCertificateUri),
					tpm.WithImaLogs(withImaLogs),
					tpm.WithUefiEventLogs(withEventLogs),
				}

				tpmAdapter, err := tpmAdapterFactory.New(tpmOptions...)
				if err != nil {
					return err
				}

				builderOptions = append(builderOptions, connector.WithEvidenceAdapter(tpmAdapter))
			}

			if withTdx {
				tdxAdapter, err := tdxAdapterFactory.New(cfg.CloudProvider, withCcel)
				if err != nil {
					return errors.Wrap(err, "Error while creating tdx adapter")
				}

				builderOptions = append(builderOptions, connector.WithEvidenceAdapter(tdxAdapter))
			}

			if withNvGpu {
				gpuAdapter := nvgpu.NewCompositeEvidenceAdapter()
				builderOptions = append(builderOptions, connector.WithEvidenceAdapter(gpuAdapter))
			}

			if !noVerifierNonce {
				// only create the connector if the user has opted to include a verifier
				// nonce
				if cfg.TrustAuthorityApiUrl == "" {
					return errors.New("The Trust Authority API URL must be present in config")
				}

				ctr, err = ctrFactory.NewConnector(&connector.Config{
					ApiUrl: cfg.TrustAuthorityApiUrl,
					ApiKey: cfg.TrustAuthorityApiKey,
					TlsCfg: &tls.Config{
						CipherSuites: []uint16{
							tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
							tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						},
						InsecureSkipVerify: false,
						MinVersion:         tls.VersionTLS12,
					},
				})
				if err != nil {
					return errors.Wrap(err, "Failed to create connector")
				}

				builderOptions = append(builderOptions, connector.WithVerifierNonce(ctr))
			}

			if tokenSigningAlg != "" {
				if !connector.ValidateTokenSigningAlg(tokenSigningAlg) {
					return errors.Errorf("%q is not a valid token signing algorithm", tokenSigningAlg)
				}

				signingAlg := connector.JwtAlg(tokenSigningAlg)
				builderOptions = append(builderOptions, connector.WithTokenSigningAlgorithm(signingAlg))
			}

			evidenceBuilder, err := connector.NewEvidenceBuilder(builderOptions...)
			if err != nil {
				return err
			}

			evidence, err := evidenceBuilder.Build()
			if err != nil {
				return err
			}

			j, err := json.MarshalIndent(evidence, "", " ")
			if err != nil {
				return err
			}
			fmt.Println(string(j))
			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, constants.ConfigOptions.Name, constants.ConfigOptions.ShortHand, "", constants.ConfigOptions.Description)
	cmd.Flags().BoolVar(&withTpm, constants.WithTpmOptions.Name, false, constants.WithTpmOptions.Description)
	cmd.Flags().BoolVar(&withTdx, constants.WithTdxOptions.Name, false, constants.WithTdxOptions.Description)
	cmd.Flags().BoolVar(&withNvGpu, constants.WithNvGpuOptions.Name, false, constants.WithNvGpuOptions.Description)
	cmd.Flags().BoolVar(&noVerifierNonce, constants.NoVerifierNonceOptions.Name, false, constants.NoVerifierNonceOptions.Description)
	cmd.Flags().StringVarP(&userData, constants.UserDataOptions.Name, constants.UserDataOptions.ShortHand, "", constants.UserDataOptions.Description)
	cmd.Flags().StringVarP(&policyIds, constants.PolicyIdsOptions.Name, constants.PolicyIdsOptions.ShortHand, "", constants.PolicyIdsOptions.Description)
	cmd.Flags().StringVarP(&tokenSigningAlg, constants.TokenAlgOptions.Name, constants.TokenAlgOptions.ShortHand, "", constants.TokenAlgOptions.Description)
	cmd.Flags().BoolVar(&policiesMustMatch, constants.PolicyMustMatchOptions.Name, false, constants.PolicyMustMatchOptions.Description)
	cmd.Flags().BoolVar(&withImaLogs, constants.WithImaLogsOptions.Name, false, constants.WithImaLogsOptions.Description)
	cmd.Flags().BoolVar(&withEventLogs, constants.WithEventLogsOptions.Name, false, constants.WithEventLogsOptions.Description)
	cmd.Flags().BoolVar(&withCcel, constants.WithCcelOptions.Name, false, constants.WithCcelOptions.Description)

	if err := cmd.MarkFlagRequired(constants.ConfigOptions.Name); err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error marking flag as required:", err)
	}

	return &cmd
}
