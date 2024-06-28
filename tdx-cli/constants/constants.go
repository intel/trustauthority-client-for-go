/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package constants

const (
	RSAKeyBitLength     = 3072
	LinuxFilePathSize   = 4096
	CLIShortDescription = "Intel® Trust Authority CLI for TDX"
)

// Command Names
const (
	CreateKeyPairCmd = "create-key-pair"
	DecryptCmd       = "decrypt"
	QuoteCmd         = "quote"
	TokenCmd         = "token"
	RootCmd          = "trustauthority-cli"
	VersionCmd       = "version"
	VerifyCmd        = "verify"
	EvidenceCmd      = "evidence"
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
	TokenAlgOption        = "token-signing-alg"
	PolicyMustMatchOption = "policy-must-match"
	NoEventLogOption      = "no-eventlog"
	TokenOption           = "token"
	WithTpmOption         = "tpm"
	WithTdxOption         = "tdx"
	NoVerifierNonceOption = "no-verifier-nonce"
)
