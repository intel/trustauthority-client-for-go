/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

func loadConfig(configFile string) (*Config, error) {

	configFilePath, err := ValidateFilePath(configFile)
	if err != nil {
		return nil, errors.Wrap(err, "Invalid config file path provided")
	}
	configJson, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "Error reading config from file")
	}

	return newConfig(configJson)
}

func newConfig(configJson []byte) (*Config, error) {

	var config Config
	dec := json.NewDecoder(bytes.NewReader(configJson))
	dec.DisallowUnknownFields()
	err := dec.Decode(&config)
	if err != nil {
		return nil, errors.Wrap(err, "Error unmarshalling JSON from config")
	}

	if config.TrustAuthorityApiUrl == "" || config.TrustAuthorityApiKey == "" {
		return nil, errors.New("Either Trust Authority API URL or Trust Authority API Key is missing in config")
	}

	return &config, nil
}

func parsePolicyIds(policyIds string) ([]uuid.UUID, error) {
	var pIds []uuid.UUID
	if len(policyIds) != 0 {
		Ids := strings.Split(policyIds, ",")
		for _, id := range Ids {
			if uid, err := uuid.Parse(id); err != nil {
				return nil, errors.Errorf("Policy Id:%s is not a valid UUID", id)
			} else {
				pIds = append(pIds, uid)
			}
		}
	}

	return pIds, nil
}

// string2bytes converts a string to a byte slice. The string can be either a base64 or hex encoded string.
// The function returns nil bytes if the input string is empty.
func string2bytes(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	} else if strings.HasPrefix(s, "0x") {
		// Parse as hex
		hexStr := strings.TrimPrefix(s, "0x")
		bytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, err
		}
		return bytes, nil
	} else {
		// Parse as base64
		bytes, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		return bytes, nil
	}
}
