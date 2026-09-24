/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"os"
	"testing"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/go-tpm"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

	_ = os.WriteFile(testEvidenceFilePath, []byte(testEvidenceFileContents), 0600)
	defer os.Remove(testEvidenceFilePath)

	_ = os.WriteFile(testTpmEvidenceFilePath, []byte(testTpmEvidenceFileContents), 0600)
	defer os.Remove(testTpmEvidenceFilePath)

	_ = os.WriteFile(testBadEvidenceFilePath, []byte(testBadEvidenceFileContents), 0600)
	defer os.Remove(testBadEvidenceFilePath)

	_ = os.WriteFile(testEmptyEvidenceFilePath, []byte(testEmptyEvidenceFileContents), 0600)
	defer os.Remove(testEmptyEvidenceFilePath)

	tt := []struct {
		args            []string
		wantErr         bool
		description     string
		dependencyMocks func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory)
	}{
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
			},
			wantErr:     false,
			description: "Test with config file",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				"config-file.json",
			},
			wantErr:     true,
			description: "Test with non-existent config file",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				angryConfigFactory := MockConfigFactory{}
				angryConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{}, errors.New("Unit test failure"))

				return happyMockTdxAdapterFactory(), happyMockTpmAdapterFactory(), &angryConfigFactory, happyMockConnectorFactory()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.RequestIdOptions.Name,
				"r@q1",
			},
			wantErr:     true,
			description: "Test with malformed request id",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.PublicKeyPathOption,
				publicKeyPath,
				"--" + constants.RequestIdOptions.Name,
				"req1",
			},
			wantErr:     false,
			description: "Test with public-key file and request id",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.PublicKeyPathOption,
				"public-key.pem",
			},
			wantErr:     true,
			description: "Test with non-existent public-key file",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.UserDataOptions.Name,
				"dGVzdHVzZXJkYXRh",
				"--" + constants.PolicyIdsOptions.Name,
				"4312c813-ecb2-4e6e-83d3-515d88ac06f2",
			},
			wantErr:     false,
			description: "Test with userdata and policy ids",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.PolicyIdsOptions.Name,
				"4312c813-ecb2-4e6e-83d3-515d88ac06f2343",
			},
			wantErr:     true,
			description: "Test with invalid policy ids",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.UserDataOptions.Name,
				"u$erd@t@",
			},
			wantErr:     true,
			description: "Test with malformed userdata",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.UserDataOptions.Name,
				"dGVzdHVzZXJkYXRh",
				"--" + constants.PolicyIdsOptions.Name,
				"4312c813-ecb2-4e6e-83d3-515d88ac06f2",
				"--" + constants.TokenAlgOptions.Name,
				"PS384",
			},
			wantErr:     false,
			description: "Test with Valid PS384 alg",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.UserDataOptions.Name,
				"dGVzdHVzZXJkYXRh",
				"--" + constants.PolicyIdsOptions.Name,
				"4312c813-ecb2-4e6e-83d3-515d88ac06f2",
				"--" + constants.TokenAlgOptions.Name,
				"RS256",
				"--" + constants.PolicyMustMatchOptions.Name,
			},
			wantErr:     false,
			description: "Test with Valid RS256 alg with policy must match flag",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.UserDataOptions.Name,
				"dGVzdHVzZXJkYXRh",
				"--" + constants.PolicyIdsOptions.Name,
				"4312c813-ecb2-4e6e-83d3-515d88ac06f2",
				"--" + constants.TokenAlgOptions.Name,
				"invalid",
			},
			wantErr:     true,
			description: "Test with invalid alg",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
			},
			wantErr:     true,
			description: "MissingTrustAuthorityUrl",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				angryConfigFactory := MockConfigFactory{}
				angryConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{
					TrustAuthorityUrl:    testValidUrl,
					TrustAuthorityApiUrl: "",
					TrustAuthorityApiKey: testApiKey,
				}, nil)

				return happyMockTdxAdapterFactory(), happyMockTpmAdapterFactory(), &angryConfigFactory, happyMockConnectorFactory()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
			},
			wantErr:     true,
			description: "MissingTrustAuthorityApiKey",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				angryConfigFactory := MockConfigFactory{}
				angryConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{
					TrustAuthorityUrl:    testValidUrl,
					TrustAuthorityApiUrl: testValidUrl,
					TrustAuthorityApiKey: "",
				}, nil)

				return happyMockTdxAdapterFactory(), happyMockTpmAdapterFactory(), &angryConfigFactory, happyMockConnectorFactory()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
			},
			wantErr:     true,
			description: "MalformedTrustAuthorityApiKey",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				angryConfigFactory := MockConfigFactory{}
				angryConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{
					TrustAuthorityUrl:    testValidUrl,
					TrustAuthorityApiUrl: testValidUrl,
					TrustAuthorityApiKey: "@p!key",
				}, nil)

				return happyMockTdxAdapterFactory(), happyMockTpmAdapterFactory(), &angryConfigFactory, happyMockConnectorFactory()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.WithTpmOptions.Name,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
			},
			wantErr:     false,
			description: "TPM Adapter",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testEvidenceFilePath,
			},
			wantErr:     false,
			description: "TDX evidence from a file",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return angryMockTdxAdapterFactory(), happyMockTpmAdapterFactory(), mockConfigFactory(nil), happyMockConnectorFactory()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testTpmEvidenceFilePath,
			},
			wantErr:     false,
			description: "TPM evidence from a file",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return angryMockTdxAdapterFactory(), happyMockTpmAdapterFactory(), mockConfigFactory(nil), happyMockConnectorFactory()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testEvidenceFilePath,
				"--" + constants.PolicyIdsOptions.Name,
				"4312c813-ecb2-4e6e-83d3-515d88ac06f2",
				"--" + constants.PolicyMustMatchOptions.Name,
				"--" + constants.TokenAlgOptions.Name,
				"RS256",
				"--" + constants.RequestIdOptions.Name,
				"req1",
			},
			wantErr:     false,
			description: "Evidence file with request options",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return angryMockTdxAdapterFactory(), happyMockTpmAdapterFactory(), mockConfigFactory(nil), happyMockConnectorFactory()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testEvidenceFilePath,
				"--" + constants.TokenAlgOptions.Name,
				"invalid",
			},
			wantErr:     true,
			description: "Evidence file with an invalid signing algorithm",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testEvidenceFilePath,
				"--" + constants.PolicyIdsOptions.Name,
				"not-a-uuid",
			},
			wantErr:     true,
			description: "Evidence file with an invalid policy id",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testEvidenceFilePath,
				"--" + constants.RequestIdOptions.Name,
				"r@q1",
			},
			wantErr:     true,
			description: "Evidence file with a malformed request id",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testBadEvidenceFilePath,
			},
			wantErr:     true,
			description: "Evidence file that is not JSON",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testEmptyEvidenceFilePath,
			},
			wantErr:     true,
			description: "Evidence file with no evidence",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testNonExistentFileName,
			},
			wantErr:     true,
			description: "Evidence file that does not exist",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testEvidenceFilePath,
				"--" + constants.WithTdxOptions.Name,
			},
			wantErr:     true,
			description: "Evidence file conflicts with --tdx",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testEvidenceFilePath,
				"--" + constants.WithTpmOptions.Name,
			},
			wantErr:     true,
			description: "Evidence file conflicts with --tpm",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testEvidenceFilePath,
				"--" + constants.WithNvGpuOptions.Name,
			},
			wantErr:     true,
			description: "Evidence file conflicts with --nvgpu",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testEvidenceFilePath,
				"--" + constants.WithCcelOptions.Name,
			},
			wantErr:     true,
			description: "Evidence file conflicts with --ccel",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testEvidenceFilePath,
				"--" + constants.NoVerifierNonceOptions.Name,
			},
			wantErr:     true,
			description: "Evidence file conflicts with --no-verifier-nonce",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testEvidenceFilePath,
				"--" + constants.UserDataOptions.Name,
				"dGVzdA==",
			},
			wantErr:     true,
			description: "Evidence file conflicts with --user-data",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
		{
			args: []string{
				constants.TokenCmd,
				"--" + constants.ConfigOptions.Name,
				confFilePath,
				"--" + constants.EvidenceFileOptions.Name,
				testEvidenceFilePath,
				"--" + constants.PublicKeyPathOption,
				publicKeyPath,
			},
			wantErr:     true,
			description: "Evidence file conflicts with --pub-path",
			dependencyMocks: func() (TdxAdapterFactory, tpm.TpmAdapterFactory, ConfigFactory, connector.ConnectorFactory) {
				return createDefaultMocks()
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			cmd := newTokenCommand(tc.dependencyMocks())
			cmd.SetArgs(tc.args)

			err := cmd.Execute()
			if tc.wantErr == true {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
