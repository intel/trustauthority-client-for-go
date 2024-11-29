/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"testing"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
)

func TestEvidence(t *testing.T) {
	tests := []struct {
		name            string
		dependencyMocks func() (MockTdxAdapterFactory, MockConfigFactory, MockConnectorFactory)
		cmdArgs         []string
		errorExpected   bool
	}{
		{
			name: "Test Evidence Positive",
			dependencyMocks: func() (MockTdxAdapterFactory, MockConfigFactory, MockConnectorFactory) {
				return testEvidenceFactories()
			},
			cmdArgs: []string{ // going for positive coverage -- add "positive" arguments
				constants.EvidenceCmd,
				"--" + constants.ConfigOptions.Name,
				"doesnotexist.json",
				"--" + constants.WithTdxOptions.Name,
				"--" + constants.WithTpmOptions.Name,
				"--" + constants.NoEventLogOptions.Name,
				"--" + constants.TokenAlgOptions.Name,
				string(connector.RS256),
				"--" + constants.UserDataOptions.Name,
				"AA==",
				"--" + constants.PolicyIdsOptions.Name,
				"fe3268d7-1541-4b17-8c85-7bae3d39650f",
				"--" + constants.PolicyMustMatchOptions.Name,
			},
			errorExpected: false,
		},
		{
			name: "Test Evidence Config Failure",
			dependencyMocks: func() (MockTdxAdapterFactory, MockConfigFactory, MockConnectorFactory) {
				mockConfigFactory := MockConfigFactory{}
				mockConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{}, errors.New("Unit test failure"))
				return MockTdxAdapterFactory{}, mockConfigFactory, MockConnectorFactory{}
			},
			cmdArgs: []string{
				constants.EvidenceCmd,
				"--" + constants.ConfigOptions.Name,
				"doesnotexist.json",
				"--" + constants.WithTdxOptions.Name,
				"--" + constants.WithTpmOptions.Name,
				"--" + constants.NoEventLogOptions.Name,
			},
			errorExpected: true,
		},
		{
			name: "Test Evidence Invalid User Data",
			dependencyMocks: func() (MockTdxAdapterFactory, MockConfigFactory, MockConnectorFactory) {
				return testEvidenceFactories()
			},
			cmdArgs: []string{
				constants.EvidenceCmd,
				"--" + constants.ConfigOptions.Name,
				"doesnotexist.json",
				"--" + constants.WithTdxOptions.Name,
				"--" + constants.WithTpmOptions.Name,
				"--" + constants.NoEventLogOptions.Name,
				"--" + constants.UserDataOptions.Name,
				"notbase64",
			},
			errorExpected: true,
		},
		{
			name: "Test Evidence Invalid Policy Id",
			dependencyMocks: func() (MockTdxAdapterFactory, MockConfigFactory, MockConnectorFactory) {
				return testEvidenceFactories()
			},
			cmdArgs: []string{
				constants.EvidenceCmd,
				"--" + constants.ConfigOptions.Name,
				"doesnotexist.json",
				"--" + constants.WithTdxOptions.Name,
				"--" + constants.WithTpmOptions.Name,
				"--" + constants.NoEventLogOptions.Name,
				"--" + constants.PolicyIdsOptions.Name,
				"not-uuid",
			},
			errorExpected: true,
		},
		{
			name: "Test Evidence Invalid TPM config",
			dependencyMocks: func() (MockTdxAdapterFactory, MockConfigFactory, MockConnectorFactory) {
				mockConnector := MockConnector{}
				mockConnector.On("GetNonce", mock.Anything).Return(connector.GetNonceResponse{}, nil)

				mockConnectorFactory := MockConnectorFactory{}
				mockConnectorFactory.On("NewConnector", mock.Anything).Return(&mockConnector, nil)

				mockConfigFactory := MockConfigFactory{}
				mockConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{
					TrustAuthorityApiUrl: "https://localhost:8080",
					CloudProvider:        CloudProviderAzure,
					// Tpm: &TpmConfig{},  // TPM config is missing
				}, nil)

				mockCompositeAdapter := MockCompositeEvidenceAdapter{}
				mockCompositeAdapter.On("GetEvidenceIdentifier").Return("tdx", nil)
				mockCompositeAdapter.On("GetEvidence", mock.Anything, mock.Anything).Return(struct{}{}, nil)

				mockTdxAdapterFactory := MockTdxAdapterFactory{}
				mockTdxAdapterFactory.On("New", mock.Anything, mock.Anything).Return(&mockCompositeAdapter, nil)

				return mockTdxAdapterFactory, mockConfigFactory, mockConnectorFactory
			},
			cmdArgs: []string{
				constants.EvidenceCmd,
				"--" + constants.ConfigOptions.Name,
				"doesnotexist.json",
				"--" + constants.WithTdxOptions.Name,
				"--" + constants.WithTpmOptions.Name,
				"--" + constants.NoEventLogOptions.Name,
				"--" + constants.TokenAlgOptions.Name,
				string(connector.RS256),
			},
			errorExpected: true,
		},
		{
			name: "Test Evidence TDX Adapter Factory Failure",
			dependencyMocks: func() (MockTdxAdapterFactory, MockConfigFactory, MockConnectorFactory) {
				mockConnector := MockConnector{}
				mockConnector.On("GetNonce", mock.Anything).Return(connector.GetNonceResponse{}, nil)

				mockConnectorFactory := MockConnectorFactory{}
				mockConnectorFactory.On("NewConnector", mock.Anything).Return(&mockConnector, nil)

				mockConfigFactory := MockConfigFactory{}
				mockConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{
					TrustAuthorityApiUrl: "https://localhost:8080",
					CloudProvider:        CloudProviderAzure,
					Tpm:                  &TpmConfig{},
				}, nil)

				mockCompositeAdapter := MockCompositeEvidenceAdapter{}
				mockCompositeAdapter.On("GetEvidenceIdentifier").Return("tdx", nil)
				mockCompositeAdapter.On("GetEvidence", mock.Anything, mock.Anything).Return(struct{}{}, nil)

				mockTdxAdapterFactory := MockTdxAdapterFactory{}
				mockTdxAdapterFactory.On("New", mock.Anything, mock.Anything).Return(&mockCompositeAdapter, errors.New("Unit test failure"))

				return mockTdxAdapterFactory, mockConfigFactory, mockConnectorFactory
			},
			cmdArgs: []string{
				constants.EvidenceCmd,
				"--" + constants.ConfigOptions.Name,
				"doesnotexist.json",
				"--" + constants.WithTdxOptions.Name,
				"--" + constants.WithTpmOptions.Name,
				"--" + constants.NoEventLogOptions.Name,
			},
			errorExpected: true,
		},
		{
			name: "Test Evidence Invalid Token Alg Signature",
			dependencyMocks: func() (MockTdxAdapterFactory, MockConfigFactory, MockConnectorFactory) {
				return testEvidenceFactories()
			},
			cmdArgs: []string{
				constants.EvidenceCmd,
				"--" + constants.ConfigOptions.Name,
				"doesnotexist.json",
				"--" + constants.WithTdxOptions.Name,
				"--" + constants.WithTpmOptions.Name,
				"--" + constants.NoEventLogOptions.Name,
				"--" + constants.TokenAlgOptions.Name,
				"nottokenalg",
			},
			errorExpected: true,
		},
		{
			name: "Test Evidence Connector Factory Failure",
			dependencyMocks: func() (MockTdxAdapterFactory, MockConfigFactory, MockConnectorFactory) {
				mockConnectorFactory := MockConnectorFactory{}
				mockConnectorFactory.On("NewConnector", mock.Anything).Return(&MockConnector{}, errors.New("Unit test failure"))

				mockConfigFactory := MockConfigFactory{}
				mockConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{
					TrustAuthorityApiUrl: "https://localhost:8080",
					CloudProvider:        CloudProviderAzure,
					Tpm:                  &TpmConfig{},
				}, nil)

				mockCompositeAdapter := MockCompositeEvidenceAdapter{}
				mockCompositeAdapter.On("GetEvidenceIdentifier").Return("tdx", nil)
				mockCompositeAdapter.On("GetEvidence", mock.Anything, mock.Anything).Return(struct{}{}, nil)

				mockTdxAdapterFactory := MockTdxAdapterFactory{}
				mockTdxAdapterFactory.On("New", mock.Anything, mock.Anything).Return(&mockCompositeAdapter, nil)

				return mockTdxAdapterFactory, mockConfigFactory, mockConnectorFactory
			},
			cmdArgs: []string{
				constants.EvidenceCmd,
				"--" + constants.ConfigOptions.Name,
				"doesnotexist.json",
				"--" + constants.WithTdxOptions.Name,
				"--" + constants.WithTpmOptions.Name,
				"--" + constants.NoEventLogOptions.Name,
			},
			errorExpected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTdxAdapterFactory, mockConfigFactory, mockConnectorFactory := tt.dependencyMocks()
			cmd := newEvidenceCommand(&mockTdxAdapterFactory, &mockConfigFactory, &mockConnectorFactory)
			cmd.SetArgs(tt.cmdArgs)

			// err  | expected | result
			// ------------------------
			// nil  | false    | pass (no error and none expected)
			// !nil | false    | fail (error present but none expected)
			// nil  | true     | fail (no error but one expected)
			// !nil | true     | pass (error present and one expected)
			err := cmd.Execute()
			if err != nil && !tt.errorExpected {
				t.Errorf("An error occurred but was not expected: %v", err)
			} else if err == nil && tt.errorExpected {
				t.Errorf("Expected an error but none occurred")
			}
		})
	}
}

func testEvidenceFactories() (MockTdxAdapterFactory, MockConfigFactory, MockConnectorFactory) {
	mockConnector := MockConnector{}
	mockConnector.On("GetNonce", mock.Anything).Return(connector.GetNonceResponse{}, nil)

	mockConnectorFactory := MockConnectorFactory{}
	mockConnectorFactory.On("NewConnector", mock.Anything).Return(&mockConnector, nil)

	mockConfigFactory := MockConfigFactory{}
	mockConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{
		TrustAuthorityApiUrl: "https://localhost:8080",
		CloudProvider:        CloudProviderAzure,
		Tpm:                  &TpmConfig{},
	}, nil)

	mockCompositeAdapter := MockCompositeEvidenceAdapter{}
	mockCompositeAdapter.On("GetEvidenceIdentifier").Return("tdx", nil)
	mockCompositeAdapter.On("GetEvidence", mock.Anything, mock.Anything).Return(struct{}{}, nil)

	mockTdxAdapterFactory := MockTdxAdapterFactory{}
	mockTdxAdapterFactory.On("New", mock.Anything, mock.Anything).Return(&mockCompositeAdapter, nil)

	return mockTdxAdapterFactory, mockConfigFactory, mockConnectorFactory
}
