/*
 *   Copyright (c) 2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"os"
	"testing"

	"github.com/intel/trustconnector/tdx-cli/constants"
	"github.com/intel/trustconnector/tdx-cli/test"
	"github.com/stretchr/testify/assert"
)

var token = `
eyJhbGciOiJQUzM4NCIsImprdSI6Imh0dHBzOi8vd3d3LmludGVsLmNvbS9hbWJlci9jZXJ0cyIsImtpZCI6ImM4Mjk4OWJhMTg0ZjQ2ZmYzNjNkMjNlZDk2MTJjMGFiMzg0OWM3MTIiLCJ0eXAiOiJKV1QifQ.eyJhbWJlcl90cnVzdF9zY29yZSI6MCwiYW1iZXJfcmVwb3J0X2RhdGEiOiJmZmVhNDQwNDIzMmZhNWFmNTUzN2I0NTYyZTc5ZWZlNDQwYzI5NmUzMTlmYzkwNDAyODYxNTQyZDg2MTY1YTdkMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsImFtYmVyX3RlZV9oZWxkX2RhdGEiOiJBUUFCQU11TGRKSGJVYk9RMGFNTkJJZzVrSmJVMk82cHB1Zjh1cXRYU3AxRHR1WkFwVWVjUS9XamFENTNnMm1rS0ZndDZYUTg2bk1mMXJNNGhhVjM1cWJ0R3BJSm9sbW96NjJ6SXA1MDFhbEhLelVqVzFpNXdtYUVEbGczTStUUkR4R2pvYTBwSUVjNkE5dTFZSTFxVTZLUHh1Mmp5MXNhR2s4RXZwZGRXS1NGamNvSWp2R2c5TFJSWTMxVFNvMWJZWi9SQ0tiZTVhTFA5VGJ5ZGJpd0diNSs2VE1TUCtwT3laWHpYeEVnK051YjJpcTJqNUlkdHBDMG1xbzYwS1dsVStLcElzVkJIT0c0MXRMOENBSzBHRFJNUkZ2RnMzRGdMUkdSZ0s5d2Z4SVltdTRjRmJnS0lEM1NWcndnaGJER3d4QXlwSlByMXJuMlZkaXd1ZldSNG9zS3huUWFuM3lhN0tsTk5EaFJpY3RJd2UwVFdxeEpEZGp1RmxBSG8wcU9pVkphL1pVYzErUWxMVm5wenZlSy9BSVR2dit1TGNJYnJsRWZNT1ViRUpYc1YzWGhEeG1sRnZDb0V3YWtKT1NKVnBsQUNHSmVrWG5rclhFMjZKNTFtbHhLWTBHZlVuaWYvNUpmQnd0T253eTczZ255OFp1VGY4akhRVkxINHA0RG01TUNFdz09IiwiYW1iZXJfc2d4X21yZW5jbGF2ZSI6IjJmNjlmOTcwNzAyYTFhODVkYjM1NDc5ZWU3ZWQ4ODhmYmQ3ZmYzZTY2NjY2MTZmZjlhMWY0OTZhNzQ4YjY1MzkiLCJhbWJlcl9zZ3hfaXNfZGVidWdnYWJsZSI6ZmFsc2UsImFtYmVyX3NneF9tcnNpZ25lciI6ImQ1N2M0ZDcxZjc1MTIxNjlkNDk4NGZmNDRmOTI3MDViOWFiNTZkNmI5MzhhZDVlODcwYzA5YTFlZTMzMDVkYjIiLCJhbWJlcl9zZ3hfaXN2cHJvZGlkIjowLCJhbWJlcl9zZ3hfaXN2c3ZuIjowLCJhbWJlci1mYWl0aGZ1bC1zZXJ2aWNlLWlkcyI6WyIyZWQ4OTg0YS0zNDcwLTQ0OGEtOGRhNC0yODM4ZjY2ZDdhNDEiLCI3NDIzMmQ2Ni05MGUzLTQ4ODAtYmU4Zi02ZWRmZWMxMmYzYmEiXSwiYW1iZXJfdGNiX3N0YXR1cyI6Ik9VVF9PRl9EQVRFIiwiYW1iZXJfZXZpZGVuY2VfdHlwZSI6IlNHWCIsImFtYmVyX3NpZ25lZF9ub25jZSI6dHJ1ZSwidmVyIjoiMS4wIiwiZXhwIjoxNjcxODAwNzk4LCJqdGkiOiIxNzIxODc4ZS00ZTczLTRhNTgtODM3Ny1hNzQxNTg5YTgwNDgiLCJpYXQiOjE2NzE3OTk1NjgsImlzcyI6IkFTIEF0dGVzdGF0aW9uIFRva2VuIElzc3VlciJ9.Gb4A2jpAnYR3v3k4JF-2sN8WDwEXwhtsrK-ScODpsHJverZ7VBuCVfdsooei7QptXllhw4yIzlopFo8g0mkghj1SHtGomxQg2ficE-GulAkYJEkN5Pfzo6vXzbf6Iyil0hy9r0kRNRDVK6yJuDq_TVOsSYT2RWaLwJNOGk8in0_OuD0xKHDHQGCNKb9OJKMntP_9bS7g77vMgsjMPj9-2PEsUldE1JgB_Vy2dUP3T87HiWVMCh6TKd66R6rsFBE_WloNqdH6MVfU3UkDcETuZ-YERUIuf2rcld-uCWbI-OwwRKosi3jaI_B-6DIZx-HmhqbZWrelpW4kKKnbWNix0uxOyG1eCQdK_Hl_lYHhuKF-o9TQ94nOz_ei9YznGAKTzJSDKH2-kXlINvNN511WhEnwzWiFbUT0CDhqr7b4Hj3fWtqDWSgymttxWS04pySwC0agxkCW_PHZZFz_Gc1v5jkIpmVDYPDs_HagLVn_kakPLwVRRqaK7FWIDziST00l
`

func TestVerifyCmd(t *testing.T) {

	server := test.MockAmberServer(t)
	defer server.Close()

	configJson := `{"amber_url":"` + server.URL + `"}`
	_ = os.WriteFile(confFilePath, []byte(configJson), 0600)
	defer os.Remove(confFilePath)

	tt := []struct {
		args        []string
		wantErr     bool
		description string
	}{
		{
			args: []string{
				constants.VerifyCmd,
				"--" + constants.ConfigOption,
				confFilePath,
				"--" + constants.TokenOption,
				token,
			},
			wantErr:     true,
			description: "Test with config file and a token",
		},
		{
			args: []string{
				constants.VerifyCmd,
				"--" + constants.TokenOption,
				token,
			},
			wantErr:     true,
			description: "Test without config file",
		},
		{
			args: []string{
				constants.VerifyCmd,
				"--" + constants.ConfigOption,
				"config-file.json",
				"--" + constants.TokenOption,
				token,
			},
			wantErr:     true,
			description: "Test with non-existent config file",
		},
		{
			args: []string{
				constants.VerifyCmd,
			},
			wantErr:     true,
			description: "Test without config file or token",
		},
		{
			args: []string{
				constants.VerifyCmd,
				"--" + constants.ConfigOption,
				confFilePath,
			},
			wantErr:     true,
			description: "Test without a token",
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

func TestVerifyCmd_MissingAmberUrl(t *testing.T) {

	configJson := `{"amber_url":""}`
	_ = os.WriteFile(confFilePath, []byte(configJson), 0600)
	defer os.Remove(confFilePath)
	_, err := execute(t, rootCmd, constants.VerifyCmd, "--"+constants.ConfigOption, confFilePath, "--"+constants.TokenOption, token)
	assert.Error(t, err)
}

func TestVerifyCmd_MalformedAmberUrl(t *testing.T) {

	configJson := `{"amber_url":":amber.com"}`
	_ = os.WriteFile(confFilePath, []byte(configJson), 0600)
	defer os.Remove(confFilePath)
	_, err := execute(t, rootCmd, constants.VerifyCmd, "--"+constants.ConfigOption, confFilePath, "--"+constants.TokenOption, token)
	assert.Error(t, err)
}
