/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/go-tpm"
	"github.com/intel/trustauthority-client/tdx-cli/constants"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newProvisionAkCommand(tpmFactory tpm.TpmFactory, cfgFactory ConfigFactory, ctrFactory connector.ConnectorFactory) *cobra.Command {
	var configPath string

	cmd := cobra.Command{
		Use:          constants.ProvisionAkCmd,
		Short:        "Provisions the host's TPM with and creates and ITA signed AK certificate.",
		Long:         ``,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := cfgFactory.LoadConfig(configPath)
			if err != nil {
				return errors.Wrapf(err, "Could not read config file %q", configPath)
			}

			// create a connector that will make the AK provisioning request to ITA
			ctr, err := ctrFactory.NewConnector(&connector.Config{
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

			if cfg.Tpm == nil {
				return errors.Errorf("TPM configuration not found in config file %q", configPath)
			}

			ekHandle := cfg.Tpm.EkHandle
			if ekHandle == 0 {
				logrus.Infof("Using default EK handle: 0x%x", tpm.DefaultEkHandle)
				ekHandle = tpm.DefaultEkHandle
			}

			akHandle := cfg.Tpm.AkHandle
			if akHandle == 0 {
				logrus.Infof("Using default AK handle: 0x%x", tpm.DefaultAkHandle)
				akHandle = tpm.DefaultAkHandle
			}

			// create and open an instance of a TrustedPlatformModule that will be
			// used to allocate keys, etc. on the TPM device
			tpm, err := tpmFactory.New(tpm.TpmDeviceLinux, cfg.Tpm.OwnerAuth)
			if err != nil {
				return errors.Wrap(err, "Failed to create TPM")
			}
			defer tpm.Close()

			akCert, err := provisionAk(int(ekHandle), int(akHandle), ctr, tpm)
			if err != nil {
				return err
			}

			// print the AK certificate in PEM format to stdout
			pemBlock := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: akCert.Raw,
			}

			pemBytes := pem.EncodeToMemory(pemBlock)
			if pemBytes == nil {
				fmt.Println("Failed to encode to PEM")
				return errors.New("Failed to encode AK certificate to PEM")
			}

			fmt.Println(string(pemBytes))
			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, constants.ConfigOptions.Name, constants.ConfigOptions.ShortHand, "", constants.ConfigOptions.Description)

	return &cmd
}

func provisionAk(ekHandle int, akHandle int, ctr connector.Connector, t tpm.TrustedPlatformModule) (*x509.Certificate, error) {

	// Check if the AK handle, EK handle, and nvram index already exist
	if t.HandleExists(akHandle) {
		return nil, errors.Errorf("The AK handle 0x%x already exists.  Please delete it before running 'provision-ak'", akHandle)
	}

	if t.HandleExists(ekHandle) {
		return nil, errors.Errorf("The EK handle 0x%x already exists.  Please delete it before running 'provision-ak'", ekHandle)
	}

	// Create the EK and get its public key
	err := t.CreateEK(ekHandle)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create EK at handle 0x%x", ekHandle)
	}
	logrus.Infof("Successfully created EK at handle 0x%x", ekHandle)

	// Create the Ak and get its name
	err = t.CreateAK(akHandle, ekHandle)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create AK at handle 0x%x", akHandle)
	}
	logrus.Infof("Successfully created AK at handle 0x%x", akHandle)

	_, akTpmtPublic, _, err := t.ReadPublic(akHandle)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to read AK at handle 0x%x", akHandle)
	}

	// Get the EK certificate
	ekCert, err := t.GetEKCertificate(tpm.DefaultEkNvIndex)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to read EK certificate at nv index 0x%x", tpm.DefaultEkNvIndex)
	}

	credentialBlob, secret, cipherText, err := ctr.GetAKCertificate(ekCert, akTpmtPublic)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to retrieve AK certificate")
	}

	// Decrypt aes key that encrypts payload
	aesKey, err := t.ActivateCredential(ekHandle, akHandle, credentialBlob, secret)
	if err != nil {
		return nil, errors.Wrapf(err, "Activate credential failed")
	}

	// decrypt the ak certificate in the payload
	akDer, err := tpm.AesDecrypt(cipherText, aesKey)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to decrypt AK certificate")
	}

	// zeroize aes key
	for i := range aesKey {
		aesKey[i] = 0
	}

	// verify certificate
	akCert, err := x509.ParseCertificate(akDer)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to parse AK certificate")
	}

	return akCert, nil
}
