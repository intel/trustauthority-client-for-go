/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package constants

const (
	RSAKeyBitLength     = 3072
	CLIShortDescription = "Trust Connector for TDX"
)

// Command Names
const (
	CreateKeyPairCmd = "create-key-pair"
	DecryptCmd       = "decrypt"
	QuoteCmd         = "quote"
	TokenCmd         = "token"
	RootCmd          = "inteltrustconnector"
	VersionCmd       = "version"
	VerifyCmd        = "verify"
)

// Options Names
const (
	PrivateKeyPathOption = "key-path"
	PublicKeyPathOption  = "pub-path"
	PrivateKeyOption     = "key"
	PolicyIdsOption      = "policy-ids"
	InputOption          = "in"
	UserDataOption       = "user-data"
	NonceOption          = "nonce"
	ConfigOption         = "config"
	RequestIdOption      = "request-id"
	NoEventLogOption     = "no-eventlog"
	TokenOption          = "token"
)
