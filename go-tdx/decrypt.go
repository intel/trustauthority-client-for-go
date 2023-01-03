/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/pkg/errors"
)

// EncryptionMetadata holds information around encryption mechanism, e.g., algorithm and key used for encryption
type EncryptionMetadata struct {
	Algorithm          string
	PrivateKey         *rsa.PrivateKey
	PrivateKeyLocation string
}

// Decrypt is used to decryt the encrypted data based on provided encryption metadata
func Decrypt(encryptedData []byte, em *EncryptionMetadata) ([]byte, error) {
	priv := em.PrivateKey
	if priv == nil {
		// If Private key is not provided, read private key from file
		privateKey, err := ioutil.ReadFile(em.PrivateKeyLocation)
		if err != nil {
			return nil, errors.Wrap(err, "Error reading private key from file")
		}

		privateKeyBlock, _ := pem.Decode(privateKey)
		priv, err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "Error decoding private key")
		}
	}

	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedData, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error while decrypting data")
	}

	return decryptedData, nil
}
