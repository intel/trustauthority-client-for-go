/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"os"
	"testing"

	"github.com/intel/amber-client/tdx-cli/constants"
	"github.com/intel/amber-client/tdx-cli/test"
	"github.com/stretchr/testify/assert"
)

var pubKey = `
-----BEGIN PUBLIC KEY-----
MIIBqTCCARKgAwIBAgIIT0xFd/5uogEwDQYJKoZIhvcNAQEFBQAwFjEUMBIGA1UEAxMLZXhhbXBs
ZS5jb20wIBcNMTcwMTIwMTczOTIwWhgPOTk5OTEyMzEyMzU5NTlaMBYxFDASBgNVBAMTC2V4YW1w
bGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2Tl2MdaUFmjAaYwmEwgEVRfVqwJO4
Y+7Vxm4UqQRKNucpGUwUBo9FSvuQACpnJwHsK2WhiuSpVkunhmSx5Qb4KVSH2RT2vHBUsA3t12S2
1Vkskiya3E7QR91zZGVxZyB4gSBVhvSVXeP9+RogLLziki/VDXXKT4TIuyML1eUQ2QIDAQABMA0G
CSqGSIb3DQEBBQUAA4GBAGfw0xavZSJXxuFAwxCZBtne9BAtk+SmfKkTI21v8Tx6w/p5Yt0IIvF3
0wCES7YVZ+zUc8vtVVyk1q3f1ZqXqVvzRCjzLzQnu6VVLBaiZPH9SYNX6j0pHhBvx1ZUMopJPr2D
avTXCTSHY5JoX20KEwfu8QQXQRDUzyc0QKn9SiE3
-----END PUBLIC KEY-----
`

func TestTokenCmd(t *testing.T) {

	_ = os.WriteFile(publicKeyPath, []byte(pubKey), 0600)
	defer os.Remove(publicKeyPath)

	server := test.MockAmberServer(t)
	defer server.Close()

	configJson := `{"amber_api_url":"` + server.URL + `","amber_api_key":"YXBpa2V5"}`
	_ = os.WriteFile(confFilePath, []byte(configJson), 0600)
	defer os.Remove(confFilePath)

	tt := []struct {
		args        []string
		wantErr     bool
		description string
	}{
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOption,
				confFilePath,
			},
			wantErr:     false,
			description: "Test with config file",
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOption,
				"config-file.json",
			},
			wantErr:     true,
			description: "Test with non-existent config file",
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOption,
				confFilePath,
				"--" + constants.PublicKeyPathOption,
				publicKeyPath,
				"--" + constants.PolicyIdsOption,
				"4312c813-ecb2-4e6e-83d3-515d88ac06f2",
			},
			wantErr:     false,
			description: "Test with public-key file and policy ids",
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOption,
				confFilePath,
				"--" + constants.PublicKeyPathOption,
				"public-key.pem",
			},
			wantErr:     true,
			description: "Test with non-existent public-key file",
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOption,
				confFilePath,
				"--" + constants.UserDataOption,
				"dGVzdHVzZXJkYXRh",
				"--" + constants.PolicyIdsOption,
				"4312c813-ecb2-4e6e-83d3-515d88ac06f2",
			},
			wantErr:     false,
			description: "Test with userdata and policy ids",
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOption,
				confFilePath,
				"--" + constants.PolicyIdsOption,
				"4312c813-ecb2-4e6e-83d3-515d88ac06f2343",
			},
			wantErr:     true,
			description: "Test with invalid policy ids",
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOption,
				confFilePath,
				"--" + constants.UserDataOption,
				"u$erd@t@",
			},
			wantErr:     true,
			description: "Test with malformed userdata",
		},
	}

	for _, tc := range tt {
		_, err := execute(t, rootCmd, tc.args...)

		if tc.wantErr == true {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestTokenCmd_MissingAmberUrl(t *testing.T) {

	configJson := `{"amber_api_url":"","amber_api_key":"YXBpa2V5"}`
	_ = os.WriteFile(confFilePath, []byte(configJson), 0600)
	defer os.Remove(confFilePath)
	_, err := execute(t, rootCmd, constants.TokenCmd, "--"+constants.ConfigOption, confFilePath)
	assert.Error(t, err)
}

func TestTokenCmd_MissingAmberApiKey(t *testing.T) {

	server := test.MockAmberServer(t)
	defer server.Close()

	configJson := `{"amber_api_url":"` + server.URL + `","amber_api_key":""}`
	_ = os.WriteFile(confFilePath, []byte(configJson), 0600)
	defer os.Remove(confFilePath)
	_, err := execute(t, rootCmd, constants.TokenCmd, "--"+constants.ConfigOption, confFilePath)
	assert.Error(t, err)
}

func TestTokenCmd_MalformedAmberUrl(t *testing.T) {

	configJson := `{"amber_api_url":":amber.com","amber_api_key":"YXBpa2V5"}`
	_ = os.WriteFile(confFilePath, []byte(configJson), 0600)
	defer os.Remove(confFilePath)
	_, err := execute(t, rootCmd, constants.TokenCmd, "--"+constants.ConfigOption, confFilePath)
	assert.Error(t, err)
}

func TestTokenCmd_MalformedAmberApiKey(t *testing.T) {

	server := test.MockAmberServer(t)
	defer server.Close()

	configJson := `{"amber_api_url":"` + server.URL + `","amber_api_key":"@p!key"}`
	_ = os.WriteFile(confFilePath, []byte(configJson), 0600)
	defer os.Remove(confFilePath)
	_, err := execute(t, rootCmd, constants.TokenCmd, "--"+constants.ConfigOption, confFilePath)
	assert.Error(t, err)
}
