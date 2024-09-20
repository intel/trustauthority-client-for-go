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
	"strings"

	"github.com/intel/trustauthority-client/aztdx"
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/go-tdx"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/intel/trustauthority-client/tpm"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func newEvidenceCommand() *cobra.Command {
	var withTpm bool
	var withTdx bool
	var tokenSigningAlg string
	var noVerifierNonce bool
	var configPath string
	var policiesMustMatch bool
	var noEvLog bool
	var userData string
	var policyIds string
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

			cfg, err := loadConfig(configPath)
			if err != nil {
				return errors.Wrapf(err, "Could not read config file %q", configPath)
			}

			// connector is optionally used to get a verifier-nonce
			ctr, err = connector.New(&connector.Config{
				ApiUrl: cfg.TrustAuthorityApiUrl,
				ApiKey: cfg.TrustAuthorityApiKey,
				TlsCfg: &tls.Config{
					InsecureSkipVerify: false,
					MinVersion:         tls.VersionTLS12,
				},
			})
			if err != nil {
				return errors.Wrap(err, "Failed to create connector")
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

				tpmAdapter, err := tpm.NewCompositeEvidenceAdapterWithOptions(
					tpm.WithOwnerAuth(cfg.Tpm.OwnerAuth),
					tpm.WithAkHandle(int(cfg.Tpm.AkHandle)),
					tpm.WithPcrSelections(cfg.Tpm.PcrSelections))
				if err != nil {
					return errors.Wrap(err, "Error while creating tpm adapter")
				}

				builderOptions = append(builderOptions, connector.WithEvidenceAdapter(tpmAdapter))
			}

			if withTdx {
				var evLogParser tdx.EventLogParser
				if !noEvLog {
					evLogParser = tdx.NewEventLogParser()
				}

				var tdxAdapter connector.CompositeEvidenceAdapter
				if strings.ToLower(cfg.CloudProvider) == CloudProviderAzure {
					tdxAdapter, err = aztdx.NewCompositeEvidenceAdapter()
				} else {
					tdxAdapter, err = tdx.NewCompositeEvidenceAdapter(evLogParser)
				}

				if err != nil {
					return errors.Wrap(err, "Error while creating tdx adapter")
				}

				builderOptions = append(builderOptions, connector.WithEvidenceAdapter(tdxAdapter))
			}

			if !noVerifierNonce {
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

	cmd.Flags().StringVarP(&configPath, constants.ConfigOption, "c", "", "Trust Authority config in JSON format")
	cmd.Flags().BoolVar(&withTpm, constants.WithTpmOption, false, "Include TPM evidence in evidence output")
	cmd.Flags().BoolVar(&withTdx, constants.WithTdxOption, false, "Include TDX evidence in evidence output")
	cmd.Flags().BoolVar(&noVerifierNonce, constants.NoVerifierNonceOption, false, "Do not include an ITA verifier-nonce in evidence")
	cmd.Flags().StringVarP(&userData, constants.UserDataOption, "u", "", "User data in hex or base64 encoded format")
	cmd.Flags().StringVarP(&policyIds, constants.PolicyIdsOption, "p", "", "Trust Authority Policy Ids, comma separated")
	cmd.Flags().StringVarP(&tokenSigningAlg, constants.TokenAlgOption, "a", "", "Token signing algorithm to be used, support PS384 and RS256")
	cmd.Flags().BoolVar(&policiesMustMatch, constants.PolicyMustMatchOption, false, "When true, all policies must match for a token to be created")
	cmd.Flags().BoolVar(&noEvLog, constants.NoEventLogOption, false, "Do not collect Event Log")

	return &cmd
}