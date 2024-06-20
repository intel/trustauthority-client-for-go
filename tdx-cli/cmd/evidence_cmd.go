/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/intel/trustauthority-client/aztdx"
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/tdx-cli/config"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/intel/trustauthority-client/tpm"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func newEvidenceCommand() *cobra.Command {
	var withTpm bool
	var withTdx bool
	var withAzTdx bool
	var akHandle int
	var pcrArgs string
	var tokenSigningAlg string
	var excludeVerifierNonce bool
	var logLevel string
	var configPath string
	var policiesMustMatch bool
	var builderOptions []connector.EvidenceBuilderOption
	var ctr connector.Connector

	cmd := cobra.Command{
		Use:   constants.EvidenceCmd,
		Short: "Collects evidence from the underlying host and displays it in json format",
		Long: `Use this command to output evidence in json format.  The json can be used 
as the body of a request to the Trust Authority's /appraisal/v2/attest endpoint.
Multiple attestation types can be combined in the output using the --tpm, --tdx, 
and --az-tdx options.`,
		SilenceUsage: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			setLogLevel(logLevel)

			cfg, err := config.Load(configPath)
			if err != nil {
				return errors.Wrapf(err, "Could not read config file %q", configPath)
			}

			ctr, err = connector.NewFromOptions(
				connector.WithBaseUrl(cfg.TrustAuthorityUrl),
				connector.WithApiUrl(cfg.TrustAuthorityApiUrl),
				connector.WithApiKey(cfg.TrustAuthorityApiKey),
			)
			if err != nil {
				return errors.Wrap(err, "Failed to create connector")
			}

			userDataOption, err := cmd.Flags().GetString(constants.UserDataOption)
			if err != nil {
				return err
			}

			userData, err := string2bytes(userDataOption)
			if err != nil {
				return err
			}

			if len(userData) != 0 {
				builderOptions = append(builderOptions, connector.WithUserData(userData))
			}

			policyIdArgs, err := cmd.Flags().GetString(constants.PolicyIdsOption)
			if err != nil {
				return err
			}

			policyIds, err := parsePolicyIds(policyIdArgs)
			if err != nil {
				return err
			}

			if policyIds != nil {
				builderOptions = append(builderOptions, connector.WithPolicyIds(policyIds))
			}

			if policiesMustMatch {
				builderOptions = append(builderOptions, connector.WithPolicyMustMatch(policiesMustMatch))
			}

			if withTpm {
				// cmd line parameter takes precedence, then fallback to cfg
				if akHandle == 0 {
					akHandle = int(cfg.Tpm.AkHandle)
				}

				if pcrArgs == "" {
					pcrArgs = cfg.Tpm.PcrSelections
				}

				pcrSelections, err := parsePcrSelections(pcrArgs)
				if err != nil {
					return err
				}

				tpmAdapter, err := tpm.NewCompositeAdapter(
					tpm.WithAkHandle(akHandle),
					tpm.WithPcrSelections(pcrSelections),
				)
				if err != nil {
					return err
				}

				builderOptions = append(builderOptions, connector.WithEvidenceAdapter(tpmAdapter))
			}

			if withTdx {
				return errors.New("TDX adapter not implemented (requires dcap)")
				// builderOptions = append(builderOptions, connector.WithEvidenceAdapter(tdx.NewTdxAdapter())
			}

			if withAzTdx {
				azTdxAdapter, err := aztdx.NewAzureTdxAdapter()
				if err != nil {
					return err
				}

				builderOptions = append(builderOptions, connector.WithEvidenceAdapter(azTdxAdapter))
			}

			if !excludeVerifierNonce {
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

	cmd.Flags().StringVarP(&configPath, constants.ConfigOption, "c", "~/.tdx-cli.json", "Trust Authority config in JSON format")
	cmd.Flags().StringVarP(&logLevel, "log-level", "l", "error", "The log level used during the command [trace, debug, info, warn, error, fatal, panic]")
	cmd.Flags().BoolVar(&withTpm, constants.WithTpmOption, false, "Include TPM evidence in evidence output")
	cmd.Flags().BoolVar(&withTdx, constants.WithTdxOption, false, "Include TDX evidence in evidence output")
	cmd.Flags().BoolVar(&withAzTdx, constants.WithAzTdxOption, false, "Include Azure TDX evidence in evidence output")
	cmd.Flags().BoolVar(&excludeVerifierNonce, constants.ExcludeVerifierNonceOption, false, "Do not include an ITA verifier-nonce in evidence")
	cmd.Flags().StringP(constants.UserDataOption, "u", "", "User data in hex or base64 encoded format")
	cmd.Flags().StringP(constants.PolicyIdsOption, "p", "", "Trust Authority Policy Ids, comma separated")
	cmd.Flags().StringVarP(&pcrArgs, constants.PcrSelectionsOption, "s", "", "tpm2-tools style PCR selections, e.g. sha1:1,2,3+sha256:1,2,3")
	cmd.Flags().IntVarP(&akHandle, constants.AkHandleOption, "k", 0, "The AK handle to use when generating TPM quotes")
	cmd.Flags().StringVarP(&tokenSigningAlg, constants.TokenAlgOption, "a", "", "Token signing algorithm to be used, support PS384 and RS256")
	cmd.Flags().BoolVar(&policiesMustMatch, constants.PolicyMustMatchOption, false, "When true, all policies must match for a token to be created")

	return &cmd
}
