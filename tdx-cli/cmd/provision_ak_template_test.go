/*
 *   Copyright (c) 2022-2025 Intel Corporation
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

var testAkTemplateIndex = "0x1C100001"

func TestAkTemplateProvisioning(t *testing.T) {
	tests := []struct {
		name            string
		dependencyMocks func() (MockTpmFactory, MockConfigFactory)
		cmdArgs         []string
		errorExpected   bool
	}{
		{
			name: "Test Provision AK Template Positive",
			dependencyMocks: func() (MockTpmFactory, MockConfigFactory) {
				return testProvisionAkTemplateFactories()
			},
			cmdArgs: []string{
				constants.ProvisionAkTemplateCmd,
				"--" + constants.AkTemplateIndexOptions.Name,
				testAkTemplateIndex,
				"--" + constants.ConfigOptions.Name,
				testNonExistentFileName,
			},
			errorExpected: false,
		},
		{
			name: "Test Provision AK Template Config Failure",
			dependencyMocks: func() (MockTpmFactory, MockConfigFactory) {
				mockConfigFactory := MockConfigFactory{}
				mockConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{}, errors.New("Unit test failure"))
				return MockTpmFactory{}, mockConfigFactory
			},
			cmdArgs: []string{
				constants.ProvisionAkCmd,
				"--" + constants.AkTemplateIndexOptions.Name,
				testAkTemplateIndex,
				"--" + constants.ConfigOptions.Name,
				testNonExistentFileName,
			},
			errorExpected: true,
		},
		{
			name: "Test Provision AK TPM Template Factory Failure",
			dependencyMocks: func() (MockTpmFactory, MockConfigFactory) {
				mockTpmFactory := MockTpmFactory{}
				mockTpmFactory.On("New", mock.Anything, mock.Anything).Return(&MockTpm{}, errors.New("Unit test failure"))

				mockConfigFactory := MockConfigFactory{}
				mockConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{
					TrustAuthorityApiUrl: testValidUrl,
					CloudProvider:        CloudProviderAzure,
					Tpm:                  &TpmConfig{},
				}, nil)

				return mockTpmFactory, mockConfigFactory
			},
			cmdArgs: []string{
				constants.ProvisionAkCmd,
				"--" + constants.AkTemplateIndexOptions.Name,
				testAkTemplateIndex,
				"--" + constants.ConfigOptions.Name,
				testNonExistentFileName,
			},
			errorExpected: true,
		},
		{
			name: "Test Provision AK Template Missing Template Indx",
			dependencyMocks: func() (MockTpmFactory, MockConfigFactory) {
				mockTpmFactory := MockTpmFactory{}
				mockTpmFactory.On("New", mock.Anything, mock.Anything).Return(&MockTpm{}, errors.New("Unit test failure"))

				mockConfigFactory := MockConfigFactory{}
				mockConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{
					TrustAuthorityApiUrl: testValidUrl,
					CloudProvider:        CloudProviderAzure,
					Tpm:                  &TpmConfig{},
				}, nil)

				return mockTpmFactory, mockConfigFactory
			},
			cmdArgs: []string{
				constants.ProvisionAkCmd,
				"--" + constants.ConfigOptions.Name,
				testNonExistentFileName,
			},
			errorExpected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTpmFactory, mockConfigFactory := tt.dependencyMocks()
			cmd := newProvisionAkTemplateCommand(&mockTpmFactory, &mockConfigFactory)
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

func testProvisionAkTemplateFactories() (MockTpmFactory, MockConfigFactory) {
	mockTpm := MockTpm{}
	mockTpm.On("CreateAK", mock.Anything, mock.Anything).Return(nil)
	mockTpm.On("NVRead", mock.Anything, mock.Anything).Return([]byte{}, nil)
	mockTpm.On("HandleExists", mock.Anything, mock.Anything).Return(false)
	mockTpm.On("ReadPublic", mock.Anything).Return(testAkPub, []byte{}, []byte{}, nil)
	mockTpm.On("CreateAkFromTemplate", mock.Anything, mock.Anything).Return(nil)

	mockTpmFactory := MockTpmFactory{}
	mockTpmFactory.On("New", mock.Anything, mock.Anything).Return(&mockTpm, nil)

	mockConfigFactory := MockConfigFactory{}
	mockConfigFactory.On("LoadConfig", mock.Anything).Return(&Config{
		TrustAuthorityApiUrl: testValidUrl,
		CloudProvider:        CloudProviderAzure,
		Tpm:                  &TpmConfig{},
	}, nil)

	return mockTpmFactory, mockConfigFactory
}
