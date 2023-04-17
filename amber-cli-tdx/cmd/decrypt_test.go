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
	"github.com/intel/amber/v1/client/tdx-cli/constants"
	"github.com/intel/amber/v1/client/tdx-cli/utils"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
)

func TestDecryptCmd(t *testing.T) {

	privateKeyPem, publicKeyPem, err := utils.GenerateKeyPair()
	if err != nil {
		log.Fatal("failed to generate key pair")
	}

	err = ioutil.WriteFile(privateKeyPath, privateKeyPem, 0600)
	if err != nil {
		log.Fatal("failed to save key")
	}

	plaintText := "secret"
	block, _ := pem.Decode(privateKeyPem)
	privateKey := base64.StdEncoding.EncodeToString(block.Bytes)

	block, _ = pem.Decode(publicKeyPem)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal("failed to parse RSA encoded  public key" + err.Error())
	}

	var rsaPubKey *rsa.PublicKey
	var ok bool
	if rsaPubKey, ok = pub.(*rsa.PublicKey); !ok {
		log.Fatal("failed to parse public key")
	}

	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		rsaPubKey,
		[]byte(plaintText),
		nil,
	)
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
				"--" + constants.PrivateKeyPathOption,
				privateKeyPath,
				"--" + constants.InputOption,
				base64EncCipherText,
			},
			wantErr:     false,
			description: "Test with private-key file and encrypted blob",
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

	cleanupFiles()
}

func cleanupFiles() {
	os.Remove(privateKeyPath)
	home, _ := os.UserHomeDir()
	os.Remove(home + "/" + ".amber-cli-tdx.yaml")
	os.Remove(".amber-cli-tdx.yaml")
}
