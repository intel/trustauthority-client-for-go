/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"github.com/intel/amber/v1/client/tdx-cli/constants"
	"github.com/intel/amber/v1/client/tdx-cli/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
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

	ioutil.WriteFile("publickey.pem", []byte(pubKey), 0600)
	defer os.Remove("publickey.pem")

	server := test.MockAmberServer(t)
	defer server.Close()

	viper.Set("AMBER_URL", server.URL)
	viper.Set("AMBER_API_KEY", "YXBpa2V5")
	tt := []struct {
		args        []string
		wantErr     bool
		description string
	}{
		{
			args: []string{
				constants.TokenCmd,
			},
			wantErr:     false,
			description: "Test without inputs",
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.PolicyIdsOption,
				"4312c813-ecb2-4e6e-83d3-515d88ac06f2",
			},
			wantErr:     false,
			description: "Test with all valid inputs",
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.PolicyIdsOption,
				"4312c813-ecb2-4e6e-83d3-515d88ac06f2343",
			},
			wantErr:     true,
			description: "Test with invalid policy ids",
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
