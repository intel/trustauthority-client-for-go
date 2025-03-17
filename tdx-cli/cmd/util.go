/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/intel/trustauthority-client/tdx-cli/constants"
	"github.com/pkg/errors"
)

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

func ValidateFilePath(path string) (string, error) {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return "", errors.Wrap(ErrInvalidFilePath, "path cannot be directory, please provide file path")
	}
	cleanedPath := filepath.Clean(path)
	if err := checkFilePathForInvalidChars(cleanedPath); err != nil {
		return "", errors.Wrap(ErrInvalidFilePath, err.Error())
	}
	r, err := filepath.EvalSymlinks(cleanedPath)
	if err != nil && !os.IsNotExist(err) {
		return cleanedPath, errors.Wrap(ErrInvalidFilePath, "Unsafe symlink detected in path")
	}
	if r == "" {
		return cleanedPath, nil
	}
	if err = checkFilePathForInvalidChars(r); err != nil {
		return "", errors.Wrap(ErrInvalidFilePath, err.Error())
	}
	return r, nil
}

func checkFilePathForInvalidChars(path string) error {
	filePath, fileName := filepath.Split(path)
	//Max file path length allowed in linux is 4096 characters
	if len(path) > constants.LinuxFilePathSize || !filePathRegex.MatchString(filePath) {
		return errors.New("Invalid file path provided")
	}
	if !fileNameRegex.MatchString(fileName) {
		return errors.New("Invalid file name provided")
	}
	return nil
}
