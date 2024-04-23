/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package cmd

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/intel/trustauthority-client/tpm"
	"github.com/sirupsen/logrus"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// please report any bugs in this code to github copilot ;-)
func parsePolicyIds(policyIds string) ([]uuid.UUID, error) {
	var uuids []uuid.UUID
	if policyIds == "" {
		return uuids, nil
	}

	if !strings.Contains(policyIds, ",") {
		parsedUUID, err := uuid.Parse(policyIds)
		if err != nil {
			return nil, errors.New("policyIds must be a valid UUID")
		}
		return []uuid.UUID{parsedUUID}, nil
	}
	ids := strings.Split(policyIds, ",")
	uuids = make([]uuid.UUID, len(ids))

	for i, id := range ids {
		parsedUUID, err := uuid.Parse(id)
		if err != nil {
			return nil, err
		}
		uuids[i] = parsedUUID
	}

	return uuids, nil
}

func setLogLevel(logLevel string) {
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		fmt.Printf("Failed to parse log level %q, 'info' will be used", logLevel)
		level = logrus.ErrorLevel
	}
	logrus.SetLevel(level)

	// Add the file/line number to log statements when debugging
	if level <= logrus.DebugLevel {
		logrus.SetReportCaller(true)
	}
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

func parsePcrSelections(args string) ([]tpm.PcrSelection, error) {
	pcrSelections := []tpm.PcrSelection{}

	if args == "" {
		return pcrSelections, nil
	}

	// tpm2-tools like selection strings "sha1:1,2,3+sha256:1,2,3"
	selections := strings.Split(args, "+")
	for _, selection := range selections {
		pcrSelection := tpm.PcrSelection{}

		// Split the selection
		parts := strings.Split(selection, ":")
		if len(parts) != 2 {
			return nil, errors.New("invalid format")
		}

		hash := parts[0]
		switch hash {
		case "sha1":
			pcrSelection.Hash = crypto.SHA1
		case "sha256":
			pcrSelection.Hash = crypto.SHA256
		case "sha384":
			pcrSelection.Hash = crypto.SHA384
		case "sha512":
			pcrSelection.Hash = crypto.SHA512
		default:
			return nil, errors.Errorf("Invalid PCR hash %q", hash)
		}

		// Parse the array of pcr banks
		intsStr := parts[1]
		banks := strings.Split(intsStr, ",")
		for _, str := range banks {
			bank, err := strconv.Atoi(str)
			if err != nil {
				return nil, errors.Errorf("Failed to parse PCR bank %q", str)
			}
			if bank < 0 || bank > 23 {
				return nil, errors.Errorf("Bank %d out of range", bank)
			}
			pcrSelection.Pcrs = append(pcrSelection.Pcrs, bank)
		}

		pcrSelections = append(pcrSelections, pcrSelection)
	}

	return pcrSelections, nil
}
