/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package cmd

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
)

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
	if len(data) == 0 {
		*hi = HexInt(0)
		return nil
	}

	var hexStr string
	err := json.Unmarshal(data, &hexStr)
	if err != nil {
		return err
	}

	if hexStr == "" {
		*hi = HexInt(0)
		return nil
	}

	// Remove the "0x" prefix from the hex string if provided
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
