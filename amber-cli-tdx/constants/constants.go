/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package constants

const (
	MaxKeyLen              = 256
	PemBlockTypePrivateKey = "PRIVATE KEY"
	PemBlockTypePubliceKey = "PUBLIC KEY"
	PublicKeyFileName      = "public-key.pem"
	RSAKeyBitLength        = 3072
	CLIShortDescription    = "Amber Attestation Client for TDX"
)

// Command Names
const (
	CreateKeyPairCmd = "create-key-pair"
	DecryptCmd       = "decrypt"
	QuoteCmd         = "quote"
	TokenCmd         = "token"
	RootCmd          = "amber-cli"
	VersionCmd       = "version"
)

// Options Names
const (
	PrivateKeyPathOption = "key-path"
	PrivateKeyOption     = "key"
	PolicyIdsOption      = "policy-ids"
	InputOption          = "in"
	UserDataOption       = "user-data"
	NonceOption          = "nonce"
)

const (
	AmberApiKeyEnv = "AMBER_API_KEY"
	AmberUrlEnv    = "AMBER_URL"
)
