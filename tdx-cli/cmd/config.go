/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

type Config struct {
	CloudProvider        string     `json:"cloud_provider"`
	TrustAuthorityUrl    string     `json:"trustauthority_url"`
	TrustAuthorityApiUrl string     `json:"trustauthority_api_url"`
	TrustAuthorityApiKey string     `json:"trustauthority_api_key"`
	Tpm                  *TpmConfig `json:"tpm,omitempty"`
}

type TpmConfig struct {
	// AkHandle is the handle of the TPM key that will be used to sign TPM quotes
	AkHandle HexInt `json:"ak_handle"`
	// EkHandle is needed during AK provisioning to create the AK
	EkHandle HexInt `json:"ek_handle"`
	// OwnerAuth is the owner password of the TPM (defaults to "")
	OwnerAuth string `json:"owner_auth"`
	// PcrSelections is the list of PCR banks and indices that are included in TPM quotes
	PcrSelections string `json:"pcr_selections"`
	// AkCertificateUri is the URI of the AK certificate.  Currently, "file://{full path}" and
	// "nvram://{index in hex}" are supported.
	AkCertificateUri string `json:"ak_certificate"`
}

type ConfigFactory interface {
	LoadConfig(configFile string) (*Config, error)
}

func NewConfigFactory() ConfigFactory {
	return &configFactory{}
}

type configFactory struct{}

func (c *configFactory) LoadConfig(configFile string) (*Config, error) {
	return loadConfig(configFile)
}
