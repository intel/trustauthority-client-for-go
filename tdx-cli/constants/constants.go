/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package constants

const (
	RSAKeyBitLength     = 3072
	LinuxFilePathSize   = 4096
	CLIShortDescription = "Intel® Trust Authority CLI"
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
	ProvisionAkCmd   = "provision-ak"
)

// Options Names
const (
	PrivateKeyPathOption = "key-path"
	PublicKeyPathOption  = "pub-path"
	PrivateKeyOption     = "key"
	InputOption          = "in"
	NonceOption          = "nonce"
	TokenOption          = "token"
	WithAzTdxOption      = "aztdx"
)

type CommandOptions struct {
	Name        string
	ShortHand   string
	Description string
}

var (
	ConfigOptions          = CommandOptions{"config", "c", "Trust Authority config in JSON format"}
	WithTpmOptions         = CommandOptions{"tpm", "", "Include TPM evidence in evidence output"}
	WithTdxOptions         = CommandOptions{"tdx", "", "Include TDX evidence in evidence output (root privileges required)"}
	WithNvGpuOptions       = CommandOptions{"nvgpu", "", "Include NVGPU evidence in evidence output"}
	NoVerifierNonceOptions = CommandOptions{"no-verifier-nonce", "", "Do not include an ITA verifier-nonce in evidence"}
	UserDataOptions        = CommandOptions{"user-data", "u", "User data in base64 encoded format"}
	PolicyIdsOptions       = CommandOptions{"policy-ids", "p", "Trust Authority Policy Ids, comma separated"}
	TokenAlgOptions        = CommandOptions{"token-signing-alg", "a", "Token signing algorithm to be used, support PS384 and RS256"}
	PolicyMustMatchOptions = CommandOptions{"policy-must-match", "", "When set, the policy_must_match flag will be true in evidence output"}
	WithImaLogsOptions     = CommandOptions{"ima", "", "When set, TPM evidence will include IMA runtime measurements"}
	WithEventLogsOptions   = CommandOptions{"evl", "", "When set, TPM evidence will include UEFI event logs"}
	WithCcelOptions        = CommandOptions{"ccel", "", "When set, TDX evidence will include Confidential Computing Event Logs"}
	RequestIdOptions       = CommandOptions{"request-id", "r", "Request ID for the token"}
)
