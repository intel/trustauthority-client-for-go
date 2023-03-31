/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/intel/amber/v1/client/tdx"
	"github.com/intel/amber/v1/client/tdx-cli/constants"
	"github.com/pkg/errors"
)

func GenerateKeyPair() ([]byte, []byte, error) {
	keyPair, err := rsa.GenerateKey(rand.Reader, constants.RSAKeyBitLength)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error while generating RSA key pair")
	}
	defer tdx.ZeroizeRSAPrivateKey(keyPair)

	privateKey := &pem.Block{
		Type:  constants.PemBlockTypePrivateKey,
		Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
	}
	defer tdx.ZeroizeByteArray(privateKey.Bytes)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&keyPair.PublicKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error when dumping publickey")
	}

	pubKeyPem := &pem.Block{
		Type:  constants.PemBlockTypePubliceKey,
		Bytes: publicKeyBytes,
	}

	return pem.EncodeToMemory(privateKey), pem.EncodeToMemory(pubKeyPem), nil
}
