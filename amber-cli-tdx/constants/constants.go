/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package constants

import "regexp"

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
	TLSVerifyOption             = "use-secure-cert"
	PrivateKeyPathOption        = "key-path"
	PolicyIdsOption             = "policy-ids"
	DecryptCmdInputOption       = "in"
	DecryptedDataFilePathOption = "out"
	UserDataOption              = "user-data"
	NonceOption                 = "nonce"
)

const (
	AmberApiKeyEnv = "AMBER_API_KEY"
	AmberUrlEnv    = "AMBER_URL"
)

var HexReg = regexp.MustCompile(`^[A-Fa-f0-9]+$`)
var StringReg = regexp.MustCompile("(^[a-zA-Z0-9_ \\/.-]*$)")
