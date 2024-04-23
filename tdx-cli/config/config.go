/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"github.com/intel/trustauthority-client/go-connector"
)

type Config struct {
	TrustAuthorityUrl    string     `json:"trustauthority_url"`
	TrustAuthorityApiUrl string     `json:"trustauthority_api_url"`
	TrustAuthorityApiKey string     `json:"trustauthority_api_key"`
	Tpm                  *TpmConfig `json:"tpm,omitempty"`
}

type TpmConfig struct {
	AkHandle      HexInt `json:"ak_handle"`
	OwnerAuth     string `json:"owner_auth"`
	PcrSelections string `json:"pcr_selections"`
}

func New() *Config {
	return &Config{
		TrustAuthorityApiUrl: connector.DefaultApiUrl,
		TrustAuthorityUrl:    connector.DefaultBaseUrl,
	}
}

func Load(path string) (*Config, error) {
	filePath := expandHomeDir(path)

	j, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	cfg := New() // apply defaults first and override them with json decoder

	decoder := json.NewDecoder(bytes.NewReader(j))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func (cfg *Config) Save(path string) error {
	filePath := expandHomeDir(path)

	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	err = os.WriteFile(filePath, b, 0600)
	if err != nil {
		return err
	}

	return nil
}

func expandHomeDir(path string) string {
	expanded := path
	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	if strings.HasPrefix(path, "~") {
		expanded = strings.Replace(expanded, "~", homeDir, 1)
	}

	return expanded
}

// Copilot code:  log any bugs with github
type HexInt int

func (hi HexInt) MarshalJSON() ([]byte, error) {
	// Convert the integer value of HexInt to bytes
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, uint32(hi))

	// Convert the bytes to a hex string
	hexStr := "0x" + hex.EncodeToString(bytes)

	// Marshal the hex string to JSON
	return json.Marshal(hexStr)
}

func (hi *HexInt) UnmarshalJSON(data []byte) error {
	var hexStr string
	err := json.Unmarshal(data, &hexStr)
	if err != nil {
		return err
	}

	// Remove the "0x" prefix from the hex string
	hexStr = strings.TrimPrefix(hexStr, "0x")

	// Convert the hex string to bytes
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return err
	}

	// Convert the bytes to an integer
	intVal := int(binary.BigEndian.Uint32(bytes))

	// Set the value of HexInt to the integer
	*hi = HexInt(intVal)

	return nil
}
