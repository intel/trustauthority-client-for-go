/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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
				return nil, errors.Errorf("Policy Id:%q is not a valid UUID", id)
			} else {
				pIds = append(pIds, uid)
			}
		}
	}

	return pIds, nil
}

// evidenceRequestOptions are the top level keys of an attestation request that
// describe the request rather than the evidence itself. They come from command
// line options, not from what a TEE collected.
var evidenceRequestOptions = []string{"policy_ids", "policy_must_match", "token_signing_alg"}

// maxEvidenceFileSize caps what readEvidenceFile will read. The Trust Authority
// rejects request bodies over 500,000 bytes, so anything approaching that cannot
// be attested anyway.
const maxEvidenceFileSize = 512 * 1024

// readEvidenceFile reads attestation evidence from a JSON file, in the format
// the evidence command produces.
//
// The evidence is kept as an unstructured map so that it reaches the Trust
// Authority as it was collected. The CLI deliberately does not interpret the
// per-TEE payloads, which keeps this independent of the evidence types the
// client supports, including composite evidence combining several of them.
func readEvidenceFile(path string) (map[string]interface{}, error) {
	evidencePath, err := ValidateFilePath(path)
	if err != nil {
		return nil, errors.Wrap(err, "Invalid evidence file path provided")
	}

	info, err := os.Stat(evidencePath)
	if err != nil {
		return nil, errors.Wrap(err, "Error reading evidence file")
	}
	if info.Size() > maxEvidenceFileSize {
		return nil, errors.Errorf("Evidence file is larger than %d bytes", maxEvidenceFileSize)
	}

	contents, err := os.ReadFile(evidencePath)
	if err != nil {
		return nil, errors.Wrap(err, "Error reading evidence file")
	}

	var evidence map[string]interface{}
	if err := json.Unmarshal(contents, &evidence); err != nil {
		return nil, errors.Wrapf(err, "Error while parsing evidence file %q", path)
	}

	// Require at least one key that is not a request option, so a file holding no
	// evidence fails here rather than at the Trust Authority. The remaining keys
	// are the evidence identifiers ("tdx", "tpm", ...) and are not inspected.
	for key := range evidence {
		if !slices.Contains(evidenceRequestOptions, key) {
			return evidence, nil
		}
	}

	return nil, errors.Errorf("Evidence file %q does not contain any evidence", path)
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
