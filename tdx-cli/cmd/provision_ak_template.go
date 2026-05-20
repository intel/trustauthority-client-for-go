/*
 *   Copyright (c) 2022-2025 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"github.com/intel/trustauthority-client/go-tpm"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newProvisionAkTemplateCommand(tpmFactory tpm.TpmFactory, cfgFactory ConfigFactory) *cobra.Command {
	var configPath string
	var akTemplateIdx int

	cmd := cobra.Command{
		Use:          constants.ProvisionAkTemplateCmd,
		Short:        "Provisions the host's TPM with an AK derived from an template in nvram.",
		Long:         ``,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := cfgFactory.LoadConfig(configPath)
			if err != nil {
				return errors.Wrapf(err, "Could not read config file %q", configPath)
			}

			if cfg.Tpm == nil {
				return errors.Errorf("TPM configuration not found in config file %q", configPath)
			}

			akHandle := cfg.Tpm.AkHandle
			if akHandle == 0 {
				logrus.Infof("Using default AK handle: 0x%x", tpm.DefaultAkHandle)
				akHandle = tpm.DefaultAkHandle
			}

			if akTemplateIdx == 0 {
				return errors.Errorf("the AK template's nvram index must be provided in the %q option", constants.AkTemplateIndexOptions.Name)
			}

			// create and open an instance of a TrustedPlatformModule that will be
			// used to allocate keys, etc. on the TPM device
			tpm, err := tpmFactory.New(tpm.TpmDeviceLinux, cfg.Tpm.OwnerAuth)
			if err != nil {
				return errors.Wrap(err, "Failed to create TPM")
			}
			defer tpm.Close()

			err = provisionAkTemplate(int(akHandle), akTemplateIdx, tpm)
			if err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, constants.ConfigOptions.Name, constants.ConfigOptions.ShortHand, "", constants.ConfigOptions.Description)
	cmd.Flags().IntVarP(&akTemplateIdx, constants.AkTemplateIndexOptions.Name, constants.AkTemplateIndexOptions.ShortHand, 0, constants.AkTemplateIndexOptions.Description)
	return &cmd
}

func provisionAkTemplate(akHandle int, akTemplateIdx int, t tpm.TrustedPlatformModule) error {

	// Check if the AK handle, EK handle, and nvram index already exist
	if t.HandleExists(akHandle) {
		return errors.Errorf("The AK handle 0x%x already exists.  Please delete it before running %q", akHandle, constants.ProvisionAkTemplateCmd)
	}

	akTemplate, err := t.NVRead(akTemplateIdx)
	if err != nil {
		return errors.Wrapf(err, "Failed to read AK template at index %d", akTemplateIdx)
	}

	// Create the Ak and get its name
	err = t.CreateAkFromTemplate(akHandle, akTemplate)
	if err != nil {
		return errors.Wrapf(err, "Failed to create AK at handle 0x%x", akHandle)
	}
	logrus.Infof("Successfully created AK at handle 0x%x", akHandle)

	return nil
}
