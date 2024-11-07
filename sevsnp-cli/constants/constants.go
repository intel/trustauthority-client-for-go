/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package constants

const (
	RSAKeyBitLength     = 3072
	CLIShortDescription = "Intel® Trust Authority CLI for sevsnp"
)

// Command Names
const (
	CreateKeyPairCmd = "create-key-pair"
	DecryptCmd       = "decrypt"
	ReportCmd        = "report"
	TokenCmd         = "token"
	RootCmd          = "trustauthority-sevsnp-cli"
	VersionCmd       = "version"
	VerifyCmd        = "verify"
)

// Options Names
const (
	PrivateKeyPathOption  = "key-path"
	PublicKeyPathOption   = "pub-path"
	PrivateKeyOption      = "key"
	PolicyIdsOption       = "policy-ids"
	InputOption           = "in"
	UserDataOption        = "user-data"
	NonceOption           = "nonce"
	ConfigOption          = "config"
	RequestIdOption       = "request-id"
	TokenOption           = "token"
	TokenAlgOption        = "token-signing-alg"
	PolicyMustMatchOption = "policy-must-match"
	UserVmplOption        = "vmpl"
)
