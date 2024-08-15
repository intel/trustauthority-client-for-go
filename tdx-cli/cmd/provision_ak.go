/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/intel/trustauthority-client/tpm"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newProvisionAkCommand() *cobra.Command {
	var configPath string

	cmd := cobra.Command{
		Use:          constants.ProvisionAkCmd,
		Short:        "Provisions the host's TPM with and creates and ITA signed AK certificate.",
		Long:         ``,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(configPath)
			if err != nil {
				return errors.Wrapf(err, "Could not read config file %q", configPath)
			}

			// create a connector that will make the AK provisioning request to ITA
			ctr, err := connector.New(&connector.Config{
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

			// create and open an instance of a TrustedPlatformModule that will be
			// used to allocate keys, etc. on the TPM device
			tpm, err := tpm.New(tpm.WithTpmOwnerAuth(cfg.Tpm.OwnerAuth))
			if err != nil {
				return errors.Wrap(err, "Failed to create TPM")
			}
			defer tpm.Close()

			akCert, err := provisionAk(int(cfg.Tpm.EkHandle), int(cfg.Tpm.AkHandle), ctr, tpm)
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
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

	cmd.Flags().StringVarP(&configPath, constants.ConfigOption, "c", "", "Trust Authority config in JSON format")

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
		return nil, err
	}
	logrus.Debugf("Successfully created EK at handle %x\n", ekHandle)

	// Create the Ak and get its name
	err = t.CreateAK(akHandle, ekHandle)
	if err != nil {
		return nil, err
	}
	logrus.Debugf("Successfully created AK at handle %x\n", akHandle)

	akPublic, akName, _, err := t.ReadPublic(akHandle)
	if err != nil {
		return nil, err
	}

	rsaAkPub, ok := akPublic.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Failed to convert the AK public to RSA public key")
	}

	// Get the EK certificate
	ekCert, err := t.GetEKCertificate(tpm.DefaultEkNvIndex)
	if err != nil {
		return nil, err
	}

	credentialBlob, secret, payload, err := ctr.GetAKCertificate(ekCert, rsaAkPub, akName)
	if err != nil {
		return nil, err
	}

	// Decrypt aes key that encrypts payload
	aesKey, err := t.ActivateCredential(ekHandle, akHandle, credentialBlob, secret)
	if err != nil {
		return nil, err
	}

	// decrypt the ak certificate in the payload
	akDer, err := aesDecrypt(payload, aesKey)
	if err != nil {
		return nil, err
	}

	// verify certificate
	akCert, err := x509.ParseCertificate(akDer)
	if err != nil {
		return nil, err
	}

	return akCert, nil
}

func aesDecrypt(cipherText, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("invalid parameter. length of key is zero")
	}
	// generate a new aes cipher using key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	// here we decrypt data using the Open function
	plaintext, err := gcm.Open(nil, cipherText[:nonceSize], cipherText[nonceSize:], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
