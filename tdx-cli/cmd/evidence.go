/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"

	"github.com/intel/trustauthority-client/go-connector"
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
	var tokenSigningAlg string
	var noVerifierNonce bool
	var configPath string
	var policiesMustMatch bool
	var noEvLog bool
	var userData string
	var policyIds string
	var withImaLogs bool
	var withEventLogs bool
	var eventLogsPath string
	var imaLogsPath string
	var builderOptions []connector.EvidenceBuilderOption
	var ctr connector.Connector

	cmd := cobra.Command{
		Use:   constants.EvidenceCmd,
		Short: "Collects evidence from the underlying host and displays it in json format",
		Long: `Use this command to output evidence in json format.  The json can be used 
 as the body of a request to the Trust Authority's /appraisal/v2/attest endpoint.
 Multiple attestation types can be combined in the output using the --tpm and --tdx
 options.`,
		SilenceUsage: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {

			cfg, err := cfgFactory.LoadConfig(configPath)
			if err != nil {
				return errors.Wrapf(err, "Could not read config file %q", configPath)
			}

			userData, err := string2bytes(userData)
			if err != nil {
				return err
			}
			if len(userData) != 0 {
				builderOptions = append(builderOptions, connector.WithUserData(userData))
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

			if withTpm {
				if cfg.Tpm == nil {
					return errors.Errorf("TPM configuration not found in config file %q", configPath)
				}

				tpmOptions := []tpm.TpmAdapterOptions{
					tpm.WithOwnerAuth(cfg.Tpm.OwnerAuth),
					tpm.WithAkHandle(int(cfg.Tpm.AkHandle)),
					tpm.WithPcrSelections(cfg.Tpm.PcrSelections),
					tpm.WithAkCertificateUri(cfg.Tpm.AkCertificateUri),
				}

				if withImaLogs {
					tpmOptions = append(tpmOptions, tpm.WithImaLogs(imaLogsPath))
				}

				if withEventLogs {
					tpmOptions = append(tpmOptions, tpm.WithUefiEventLogs(eventLogsPath))
				}

				tpmAdapter, err := tpmAdapterFactory.New(tpmOptions...)
				if err != nil {
					return err
				}

				builderOptions = append(builderOptions, connector.WithEvidenceAdapter(tpmAdapter))
			}

			if withTdx {
				tdxAdapter, err := tdxAdapterFactory.New(cfg.CloudProvider, noEvLog)
				if err != nil {
					return errors.Wrap(err, "Error while creating tdx adapter")
				}

				builderOptions = append(builderOptions, connector.WithEvidenceAdapter(tdxAdapter))
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

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
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
	cmd.Flags().BoolVar(&noVerifierNonce, constants.NoVerifierNonceOptions.Name, false, constants.NoVerifierNonceOptions.Description)
	cmd.Flags().StringVarP(&userData, constants.UserDataOptions.Name, constants.UserDataOptions.ShortHand, "", constants.UserDataOptions.Description)
	cmd.Flags().StringVarP(&policyIds, constants.PolicyIdsOptions.Name, constants.PolicyIdsOptions.ShortHand, "", constants.PolicyIdsOptions.Description)
	cmd.Flags().StringVarP(&tokenSigningAlg, constants.TokenAlgOptions.Name, constants.TokenAlgOptions.ShortHand, "", constants.TokenAlgOptions.Description)
	cmd.Flags().BoolVar(&policiesMustMatch, constants.PolicyMustMatchOptions.Name, false, constants.PolicyMustMatchOptions.Description)
	cmd.Flags().BoolVar(&noEvLog, constants.NoEventLogOptions.Name, false, constants.NoEventLogOptions.Description)
	cmd.Flags().BoolVar(&withImaLogs, constants.WithImaLogsOptions.Name, false, constants.WithImaLogsOptions.Description)
	cmd.Flags().BoolVar(&withEventLogs, constants.WithEventLogsOptions.Name, false, constants.WithEventLogsOptions.Description)
	cmd.Flags().StringVarP(&eventLogsPath, constants.EventLogsPathOptions.Name, constants.EventLogsPathOptions.ShortHand, "", constants.EventLogsPathOptions.Description)
	cmd.Flags().StringVarP(&imaLogsPath, constants.ImaLogsPathOptions.Name, constants.ImaLogsPathOptions.ShortHand, "", constants.ImaLogsPathOptions.Description)

	return &cmd
}
