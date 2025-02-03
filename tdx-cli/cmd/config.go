/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"bytes"
	"encoding/json"
	"os"

	"github.com/pkg/errors"
)

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
	configFilePath, err := ValidateFilePath(configFile)
	if err != nil {
		return nil, errors.Wrapf(err, "Invalid config file path %q provided", configFile)
	}
	configJson, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "Error reading config file %q", configFile)
	}

	cfg, err := newConfig(configJson)
	if err != nil {
		return nil, errors.Wrapf(err, "Error parsing config from file %q", configFile)

	}

	return cfg, nil
}

func newConfig(configJson []byte) (*Config, error) {
	var config Config
	dec := json.NewDecoder(bytes.NewReader(configJson))
	dec.DisallowUnknownFields()
	err := dec.Decode(&config)
	if err != nil {
		return nil, errors.Wrap(ErrMalformedJson, err.Error())
	}

	return &config, nil
}
