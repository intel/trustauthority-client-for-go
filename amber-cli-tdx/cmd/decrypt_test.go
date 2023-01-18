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

const (
	decryptedFilePath = "data"
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

	block, _ := pem.Decode(publicKeyPem)

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
				"--" + constants.DecryptCmdInputOption,
				base64EncCipherText,
			},
			wantErr: false,
			description: "Test with all valid inputs without providing value for " + constants.
				DecryptCmdOutputOption + " option",
		},
		{
			args: []string{
				constants.DecryptCmd,
				"--" + constants.PrivateKeyPathOption,
				privateKeyPath,
				"--" + constants.DecryptCmdInputOption,
				base64EncCipherText,
				"--" + constants.DecryptCmdOutputOption,
				decryptedFilePath,
			},
			wantErr: false,
			description: "Test with all valid inputs with providing value for " + constants.
				DecryptCmdOutputOption + " option",
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
	os.Remove(decryptedFilePath)
	os.Remove(privateKeyPath)

	home, _ := os.UserHomeDir()
	os.Remove(home + "/" + ".amber-cli-tdx.yaml")
	os.Remove(".amber-cli-tdx.yaml")
}
