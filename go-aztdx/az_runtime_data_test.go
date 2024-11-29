/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package aztdx

import (
	"encoding/binary"
	"testing"
)

func TestAzRuntimeDataSizeCheck(t *testing.T) {
	data := [][]byte{
		make([]byte, 0),                         // empty
		make([]byte, azRuntimeDataSizeOffset-1), // too small
		make([]byte, azRuntimeDataMaxSize+1),    // too big
	}

	for _, d := range data {
		_, err := newAzRuntimeData(d)
		if err == nil {
			t.Errorf("Expected error for data of size %d", len(d))
		}
	}
}

func TestAzRuntimeDataRuntimeSizeCheck(t *testing.T) {
	data := make([]byte, azRuntimeDataSizeOffset+4)
	binary.LittleEndian.PutUint32(data[azRuntimeDataSizeOffset:], 0x100)

	_, err := newAzRuntimeData(data)
	if err == nil {
		t.Errorf("Expected error for data of size %d", len(data))
	}
}

func TestAzRuntimeDataRuntimeBadJson(t *testing.T) {
	data := make([]byte, azRuntimeDataSizeOffset+4+0x100)
	binary.LittleEndian.PutUint32(data[azRuntimeDataSizeOffset:], 0x100)

	rt, err := newAzRuntimeData(data)
	if err != nil {
		t.Error(err)
	}

	_, err = rt.runtimeData()
	if err == nil {
		t.Error("Expected error for invalid/empty json bytes")
	}
}
