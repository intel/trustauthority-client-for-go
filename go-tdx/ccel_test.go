/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tdx

import (
	"errors"
	"testing"
)

const (
	testCcelTablePath = "test/resources/CCEL.bin"
	testCcelDataPath  = "test/resources/CCEL.data.bin"
	testInvalidPath   = "xxx"
)

func TestCcelPositive(t *testing.T) {
	ccelTable, err := readCcelTable(testCcelTablePath)
	if err != nil {
		t.Fatal(err)
	}

	_, err = readCcelData(ccelTable, testCcelDataPath)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCcelTableParserFailure(t *testing.T) {
	_, err := parseCcelTable([]byte{})
	if err == nil {
		t.Fatal("Expected error")
	}
}

func TestInvalidCcelTablePath(t *testing.T) {
	_, err := readCcelTable(testInvalidPath)
	if err == nil {
		t.Fatal("Expected error")
	}
}

func TestInvalidCcelDataPath(t *testing.T) {
	ccelTable, err := readCcelTable(testCcelTablePath)
	if err != nil {
		t.Fatal(err)
	}

	_, err = readCcelData(ccelTable, "xxx")
	if err == nil {
		t.Fatal("Expected error")
	}
}

func TestInvalidCcelTableSignature(t *testing.T) {
	ccelTable := &ccelTable{
		AcpiTableHeader: AcpiTableHeader{
			Signature: [4]byte{},
		},
	}

	err := ccelTable.validate(0)
	if err == nil || !errors.Is(err, ErrorInvalidCcelTableSignature) {
		t.Fatal("Expected error ErrorInvalidCcelDataSignature")
	}
}

func TestInvalidCcelTableLength(t *testing.T) {
	expectedLength := 100
	ccelTable := &ccelTable{
		AcpiTableHeader: AcpiTableHeader{
			Signature: [4]byte{'C', 'C', 'E', 'L'},
			Length:    uint32(expectedLength),
		},
	}

	err := ccelTable.validate(expectedLength - 1)
	if err == nil || !errors.Is(err, ErrorInvalidCcelTableLength) {
		t.Fatal("Expected error ErrorInvalidCcelTableLength")
	}
}

func TestInvalidCcelType(t *testing.T) {
	expectedLength := 100
	ccelTable := &ccelTable{
		AcpiTableHeader: AcpiTableHeader{
			Signature: [4]byte{'C', 'C', 'E', 'L'},
			Length:    uint32(expectedLength),
		},
		CCtype: 99,
	}

	err := ccelTable.validate(expectedLength)
	if err == nil || !errors.Is(err, ErrorInvalidCcelTableType) {
		t.Fatal("Expected error ErrorInvalidCcelTableType")
	}
}

func TestInvalidCcelSubType(t *testing.T) {
	expectedLength := 100
	ccelTable := &ccelTable{
		AcpiTableHeader: AcpiTableHeader{
			Signature: [4]byte{'C', 'C', 'E', 'L'},
			Length:    uint32(expectedLength),
		},
		CCtype:     CcelType,
		Ccsub_type: 99,
	}

	err := ccelTable.validate(expectedLength)
	if err == nil || !errors.Is(err, ErrorInvalidCcelTableSubType) {
		t.Fatal("Expected error ErrorInvalidCcelTableSubType")
	}
}

func TestInvalidMinimumLength(t *testing.T) {
	expectedLength := 100
	ccelTable := &ccelTable{
		AcpiTableHeader: AcpiTableHeader{
			Signature: [4]byte{'C', 'C', 'E', 'L'},
			Length:    uint32(expectedLength),
		},
		CCtype:               CcelType,
		Ccsub_type:           CcelSubType,
		LogAreaMinimumLength: 0xFFFFFFFFFFFFFFFF,
	}

	_, err := readCcelData(ccelTable, testCcelTablePath)
	if err == nil || !errors.Is(err, ErrorInvalidCcelDataMinimumLength) {
		t.Fatal("Expected error ErrorInvalidCcelDataMinimumLength")
	}
}
