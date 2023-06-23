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
	"os"

	"github.com/pkg/errors"
)

// EncryptionMetadata holds information around encryption mechanism, e.g., algorithm and key used for encryption
type EncryptionMetadata struct {
	Algorithm          string
	PrivateKey         []byte
	PrivateKeyLocation string
}

// Decrypt is used to decryt the encrypted data based on provided encryption metadata
func Decrypt(encryptedData []byte, em *EncryptionMetadata) ([]byte, error) {
	priv := em.PrivateKey
	if len(priv) == 0 {
		// If Private key is not provided, read private key from file
		privateKey, err := os.ReadFile(em.PrivateKeyLocation)
		if err != nil {
			return nil, errors.Wrapf(err, "Error reading private key from file: %s", em.PrivateKeyLocation)
		}
		defer ZeroizeByteArray(privateKey)

		privateKeyBlock, _ := pem.Decode(privateKey)
		if privateKeyBlock == nil {
			return nil, errors.New("No PEM data found in private key")
		}
		priv = privateKeyBlock.Bytes
		defer ZeroizeByteArray(priv)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(priv)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing private key")
	}
	defer ZeroizeRSAPrivateKey(privateKey)

	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedData, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error while decrypting data")
	}

	return decryptedData, nil
}
