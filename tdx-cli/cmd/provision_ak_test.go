/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"testing"

	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
)

func TestAkProvisioning(t *testing.T) {
	tests := []struct {
		name            string
		dependencyMocks func() (MockTpmFactory, MockConfigFactory, MockConnectorFactory)
		cmdArgs         []string
		errorExpected   bool
	}{
		{
			name: "Test Provision AK Positive",
			dependencyMocks: func() (MockTpmFactory, MockConfigFactory, MockConnectorFactory) {
				return testProvisionAkFactories()
			},
			cmdArgs: []string{
				constants.ProvisionAkCmd,
				"--" + constants.ConfigOptions.Name,
				"doesnotexist.json",
			},
			errorExpected: false,
		},
		{
			name: "Test Provision AK Config Failure",
			dependencyMocks: func() (MockTpmFactory, MockConfigFactory, MockConnectorFactory) {
				mockConfigFactory := MockConfigFactory{}
				mockConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{}, errors.New("Unit test failure"))
				return MockTpmFactory{}, mockConfigFactory, MockConnectorFactory{}
			},
			cmdArgs: []string{
				constants.ProvisionAkCmd,
				"--" + constants.ConfigOptions.Name,
				"doesnotexist.json",
			},
			errorExpected: true,
		},
		{
			name: "Test Provision AK Connector Factory Failure",
			dependencyMocks: func() (MockTpmFactory, MockConfigFactory, MockConnectorFactory) {
				mockTpmFactory := MockTpmFactory{}
				mockTpmFactory.On("New", mock.Anything, mock.Anything).Return(&MockTpm{}, nil)

				mockConfigFactory := MockConfigFactory{}
				mockConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{
					TrustAuthorityApiUrl: "https://localhost:8080",
					CloudProvider:        CloudProviderAzure,
					Tpm:                  &TpmConfig{},
				}, nil)

				mockConnectorFactory := MockConnectorFactory{}
				mockConnectorFactory.On("NewConnector", mock.Anything).Return(&MockConnector{}, errors.New("Unit test failure"))

				return mockTpmFactory, mockConfigFactory, mockConnectorFactory
			},
			cmdArgs: []string{
				constants.ProvisionAkCmd,
				"--" + constants.ConfigOptions.Name,
				"doesnotexist.json",
			},
			errorExpected: true,
		},
		{
			name: "Test Provision AK TPM Factory Failure",
			dependencyMocks: func() (MockTpmFactory, MockConfigFactory, MockConnectorFactory) {
				mockTpmFactory := MockTpmFactory{}
				mockTpmFactory.On("New", mock.Anything, mock.Anything).Return(&MockTpm{}, errors.New("Unit test failure"))

				mockConfigFactory := MockConfigFactory{}
				mockConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{
					TrustAuthorityApiUrl: "https://localhost:8080",
					CloudProvider:        CloudProviderAzure,
					Tpm:                  &TpmConfig{},
				}, nil)

				mockConnectorFactory := MockConnectorFactory{}
				mockConnectorFactory.On("NewConnector", mock.Anything).Return(&MockConnector{}, nil)

				return mockTpmFactory, mockConfigFactory, mockConnectorFactory
			},
			cmdArgs: []string{
				constants.ProvisionAkCmd,
				"--" + constants.ConfigOptions.Name,
				"doesnotexist.json",
			},
			errorExpected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTpmFactory, mockConfigFactory, mockConnectorFactory := tt.dependencyMocks()
			cmd := newProvisionAkCommand(&mockTpmFactory, &mockConfigFactory, &mockConnectorFactory)
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

func testProvisionAkFactories() (MockTpmFactory, MockConfigFactory, MockConnectorFactory) {
	mockTpm := MockTpm{}
	mockTpm.On("CreateEK", mock.Anything).Return(nil)
	mockTpm.On("CreateAK", mock.Anything, mock.Anything).Return(nil)
	mockTpm.On("HandleExists", mock.Anything, mock.Anything).Return(false)
	mockTpm.On("ReadPublic", mock.Anything).Return(testAkPub, []byte{}, []byte{}, nil)
	mockTpm.On("GetEKCertificate", mock.Anything).Return(testCertificate, nil)
	mockTpm.On("ActivateCredential", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(testAesKey, nil)

	mockTpmFactory := MockTpmFactory{}
	mockTpmFactory.On("New", mock.Anything, mock.Anything).Return(&mockTpm, nil)

	mockConnector := MockConnector{}
	mockConnector.On("GetAKCertificate", mock.Anything, mock.Anything).Return([]byte{}, []byte{}, testEncryptedAkCert, nil)

	mockConnectorFactory := MockConnectorFactory{}
	mockConnectorFactory.On("NewConnector", mock.Anything).Return(&mockConnector, nil)

	mockConfigFactory := MockConfigFactory{}
	mockConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{
		TrustAuthorityApiUrl: "https://localhost:8080",
		CloudProvider:        CloudProviderAzure,
		Tpm:                  &TpmConfig{},
	}, nil)

	return mockTpmFactory, mockConfigFactory, mockConnectorFactory
}
