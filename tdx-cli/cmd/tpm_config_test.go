/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"reflect"
	"testing"
)

const (
	testUrl      = "https://notused.com"
	testApiKey   = "AAAAAA=="
	testEkHandle = 0x81000F00
	testAkHandle = 0x81000F01
)

var (
	defaultConfig = Config{
		TrustAuthorityUrl:    testUrl,
		TrustAuthorityApiUrl: testUrl,
		TrustAuthorityApiKey: testApiKey,
	}

	defaultTpmConfig = TpmConfig{
		OwnerAuth: "",
		EkHandle:  HexInt(0),
		AkHandle:  HexInt(0),
	}

	defaultEmptyTpmConfig = Config{
		TrustAuthorityUrl:    testUrl,
		TrustAuthorityApiUrl: testUrl,
		TrustAuthorityApiKey: testApiKey,
		Tpm:                  &defaultTpmConfig,
	}
)

func TestConfig(t *testing.T) {

	testData := []struct {
		testName       string
		cfgJson        string
		expectedConfig *Config
		expectError    bool
	}{
		{
			// This would be applicable for customers that do not use TPM.  There
			// should be any errors with this config unless TPM is initiated (lazily).
			testName: "Nil TPM Config",
			cfgJson: `{
				 "trustauthority_url": "https://notused.com",
				 "trustauthority_api_url": "https://notused.com",
				 "trustauthority_api_key": "AAAAAA=="
			 }`,
			expectedConfig: &defaultConfig,
			expectError:    false,
		},
		{
			// Unlikely scenario but included in unit tests.  The Config object just needs
			// to be successfully parsed with "default" values (ex. 0 for handles).  The
			// TPM adapters will handle errors so that validation logic is also applicable to users
			//  the go-tpm library (i.e., via code).
			testName: "Empty TPM Config",
			cfgJson: `{
				 "trustauthority_url": "https://notused.com",
				 "trustauthority_api_url": "https://notused.com",
				 "trustauthority_api_key": "AAAAAA==",
				 "tpm": {}
			 }`,
			expectedConfig: &defaultEmptyTpmConfig,
			expectError:    false,
		},
		{
			// Unlikely scenario but included in unit tests.  The Config object just needs
			// to be successfully parsed with "default" values (ex. 0 for handles).  The
			// TPM adapters will handle errors so that validation logic is also applicable to users
			//  the go-tpm library (i.e., via code).
			testName: "Valid TPM Config with empty strings",
			cfgJson: `{
				 "trustauthority_url": "https://notused.com",
				 "trustauthority_api_url": "https://notused.com",
				 "trustauthority_api_key": "AAAAAA==",
				 "tpm": {
					 "owner_auth": "",
					 "ek_handle": "",
					 "ak_handle": ""
				 }
			 }`,
			expectedConfig: &defaultEmptyTpmConfig,
			expectError:    false,
		},
		{
			// User provides all valid values for TPM config.
			testName: "Valid, user specified TPM Config",
			cfgJson: `{
				 "trustauthority_url": "https://notused.com",
				 "trustauthority_api_url": "https://notused.com",
				 "trustauthority_api_key": "AAAAAA==",
				 "tpm": {
					 "owner_auth": "testpassword",
					 "ek_handle": "0x81000F00",
					 "ak_handle": "0x81000F01"
				 }
			 }`,
			expectedConfig: &Config{
				TrustAuthorityUrl:    testUrl,
				TrustAuthorityApiUrl: testUrl,
				TrustAuthorityApiKey: testApiKey,
				Tpm: &TpmConfig{
					OwnerAuth: "testpassword",
					EkHandle:  HexInt(testEkHandle),
					AkHandle:  HexInt(testAkHandle),
				},
			},
			expectError: false,
		},
		{
			// Ommitted AK Certificate URI, applicable to Azure TDX+vTPM
			testName: "Valid, user omitted AK Certificate URI",
			cfgJson: `{
				 "trustauthority_url": "https://notused.com",
				 "trustauthority_api_url": "https://notused.com",
				 "trustauthority_api_key": "AAAAAA==",
				 "tpm": {
					 "owner_auth": "",
					 "ek_handle": "",
					 "ak_handle": ""
				 }
			 }`,
			expectedConfig: &defaultEmptyTpmConfig,
			expectError:    false,
		},
		{
			// User provides invalid hex string for ek_handle
			testName: "Invalid hex string",
			cfgJson: `{
				 "trustauthority_url": "https://notused.com",
				 "trustauthority_api_url": "https://notused.com",
				 "trustauthority_api_key": "AAAAAA==",
				 "tpm": {
					 "owner_auth": "",
					 "ek_handle": "not-hex",
					 "ak_handle": ""
				 }
			 }`,
			expectedConfig: nil,
			expectError:    true,
		},
	}

	for _, tt := range testData {
		t.Run(tt.testName, func(t *testing.T) {
			cfg, err := newConfig([]byte(tt.cfgJson))
			if !tt.expectError && err != nil {
				t.Fatal(err)
			} else if tt.expectError && err == nil {
				t.Fatalf("newConfig() should have returned an error")
			}

			if !reflect.DeepEqual(cfg, tt.expectedConfig) {
				t.Fatalf("newConfig() returned unexpected result: expected %v, got %v", tt.expectedConfig, cfg)
			}
		})
	}
}
