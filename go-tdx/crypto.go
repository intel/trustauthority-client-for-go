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
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"hash"
	"os"
	"strings"

	"github.com/pkg/errors"
)

// KeyMetadata holds information around key creation, e.g., key length
type KeyMetadata struct {
	KeyLength int
}

// EncryptionMetadata holds information around encryption mechanism, e.g., hash algorithm and key used for encryption
type EncryptionMetadata struct {
	PrivateKey         []byte
	PrivateKeyLocation string
	HashAlgorithm      string
}

// GenerateKeyPair is used to create the private key based on provided key metadata
func GenerateKeyPair(km *KeyMetadata) ([]byte, []byte, error) {
	keyPair, err := rsa.GenerateKey(rand.Reader, km.KeyLength)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error while generating RSA key pair")
	}
	defer ZeroizeRSAPrivateKey(keyPair)

	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
	}
	defer ZeroizeByteArray(privateKey.Bytes)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&keyPair.PublicKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error when dumping publickey")
	}

	pubKeyPem := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	return pem.EncodeToMemory(privateKey), pem.EncodeToMemory(pubKeyPem), nil
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

	hash, err := getHash(em.HashAlgorithm)
	if err != nil {
		return nil, err
	}

	decryptedData, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, encryptedData, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error while decrypting data")
	}
	return decryptedData, nil
}

// getHash returns the hash object based on hash algorithm
func getHash(hashAlg string) (hash.Hash, error) {
	var digest hash.Hash

	switch strings.ToUpper(hashAlg) {
	case SHA256:
		digest = sha256.New()
	case SHA384:
		digest = sha512.New384()
	case SHA512:
		digest = sha512.New()
	default:
		return nil, errors.Errorf("Unsupported hash algorithm '%s'", hashAlg)
	}

	return digest, nil
}
