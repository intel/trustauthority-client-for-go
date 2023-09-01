/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"

	"github.com/intel/trustauthority-client/tdx-cli/constants"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestDecryptCmd(t *testing.T) {

	keyPair, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatal("failed to generate key pair")
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
	}
	privateKeyPem := pem.EncodeToMemory(block)

	_ = os.WriteFile(privateKeyPath, privateKeyPem, 0600)
	defer os.Remove(privateKeyPath)

	privateKey := base64.StdEncoding.EncodeToString(block.Bytes)
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &keyPair.PublicKey, []byte("secret"), nil)
	if err != nil {
		log.Fatal("failed to encrypt" + err.Error())
	}

	base64EncCipherText := base64.StdEncoding.EncodeToString(ciphertext)
	tt := []struct {
		args        []string
		wantErr     bool
		description string
	}{
		{
			args: []string{
				constants.DecryptCmd,
				"--" + constants.InputOption,
				base64EncCipherText,
			},
			wantErr:     true,
			description: "Test without private-key file and private key",
		},
		{
			args: []string{
				constants.DecryptCmd,
				"--" + constants.PrivateKeyPathOption,
				"private-key.pem",
				"--" + constants.InputOption,
				base64EncCipherText,
			},
			wantErr:     true,
			description: "Test with non-existent private-key file",
		},
		{
			args: []string{
				constants.DecryptCmd,
				"--" + constants.PrivateKeyOption,
				privateKey,
				"--" + constants.InputOption,
				base64EncCipherText,
			},
			wantErr:     false,
			description: "Test with private key and encrypted blob",
		},
		{
			args: []string{
				constants.DecryptCmd,
				"--" + constants.PrivateKeyOption,
				string(privateKeyPem),
				"--" + constants.InputOption,
				base64EncCipherText,
			},
			wantErr:     true,
			description: "Test with malformed private key",
		},
		{
			args: []string{
				constants.DecryptCmd,
				"--" + constants.PrivateKeyPathOption,
				privateKeyPath,
				"--" + constants.InputOption,
				"encryptedD@t@",
			},
			wantErr:     true,
			description: "Test with malformed encrypted blob",
		},
	}

	for _, tc := range tt {
		_, err := execute(t, rootCmd, tc.args...)

		if tc.wantErr == true {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}
