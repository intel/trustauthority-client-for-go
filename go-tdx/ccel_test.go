/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tdx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"testing"
)

const (
	testCcelTablePath = "test/resources/CCEL.bin"
	testCcelDataPath  = "test/resources/CCEL.data.bin"
	testInvalidPath   = "xxx"
	testCcelTableSize = 56
)

func TestCcelPositive(t *testing.T) {
	ccelBytes, err := getCcel(testCcelTablePath, testCcelDataPath)
	if err != nil {
		t.Fatal(err)
	}

	if len(ccelBytes) <= 0 {
		t.Fatal("Expected non-empty ccelBytes")
	}
}

func TestInvalidCcelTablePath(t *testing.T) {
	_, err := getCcel(testInvalidPath, testCcelDataPath)
	if !errors.Is(err, ErrorCcelTableNotFound) {
		t.Fatal("Expected ErrorCcelTableNotFound")
	}
}

func TestInvalidCcelDataPath(t *testing.T) {
	_, err := getCcel(testCcelTablePath, testInvalidPath)
	if !errors.Is(err, ErrorCcelDataNotFound) {
		t.Fatal("Expected ErrorCcelDataNotFound")
	}
}

func TestAcpiReadFailure(t *testing.T) {
	err := validateCcelData(make([]byte, 10), nil)
	if !errors.Is(err, ErrorAcpiReadFailure) {
		t.Fatal("Expected ErrorAcpiReadFailure")
	}
}

func TestInvalidCcelTableSignature(t *testing.T) {
	ccelTable := &ccelTable{
		acpiTableHeader: acpiTableHeader{
			Signature: [4]byte{},
		},
	}

	err := validateCcelData(marshalCcelTable(*ccelTable), nil)
	if !errors.Is(err, ErrorInvalidCcelTableSignature) {
		t.Fatal("Expected error ErrorInvalidCcelDataSignature")
	}
}

func TestInvalidCcelTableLength(t *testing.T) {
	ccelTable := &ccelTable{
		acpiTableHeader: acpiTableHeader{
			Signature: [4]byte{'C', 'C', 'E', 'L'},
			Length:    uint32(0),
		},
	}

	err := validateCcelData(marshalCcelTable(*ccelTable), make([]byte, testCcelTableSize))
	if !errors.Is(err, ErrorInvalidCcelTableLength) {
		t.Fatal("Expected error ErrorInvalidCcelTableLength")
	}
}

func TestInvalidCcelType(t *testing.T) {
	ccelTable := &ccelTable{
		acpiTableHeader: acpiTableHeader{
			Signature: [4]byte{'C', 'C', 'E', 'L'},
			Length:    uint32(testCcelTableSize),
		},
		CCtype: 99,
	}

	err := validateCcelData(marshalCcelTable(*ccelTable), make([]byte, testCcelTableSize))
	if !errors.Is(err, ErrorInvalidCcelTableType) {
		t.Fatal("Expected error ErrorInvalidCcelTableType")
	}
}

func TestInvalidCcelSubType(t *testing.T) {
	ccelTable := &ccelTable{
		acpiTableHeader: acpiTableHeader{
			Signature: [4]byte{'C', 'C', 'E', 'L'},
			Length:    uint32(testCcelTableSize),
		},
		CCtype:     ccelType,
		Ccsub_type: 99,
	}

	err := validateCcelData(marshalCcelTable(*ccelTable), make([]byte, testCcelTableSize))
	if !errors.Is(err, ErrorInvalidCcelTableSubType) {
		t.Fatal("Expected error ErrorInvalidCcelTableSubType")
	}
}

func TestInvalidMinimumLength(t *testing.T) {
	ccelTable := &ccelTable{
		acpiTableHeader: acpiTableHeader{
			Signature: [4]byte{'C', 'C', 'E', 'L'},
			Length:    uint32(testCcelTableSize),
		},
		CCtype:               ccelType,
		Ccsub_type:           ccelSubType,
		LogAreaMinimumLength: 0xFFFFFFFFFFFFFFFF,
	}

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, ccelTable)
	if err != nil {
		log.Fatalf("Failed to encode struct: %v", err)
	}

	dataBytes, _ := os.ReadFile(testCcelTablePath)

	err = validateCcelData(buf.Bytes(), dataBytes)
	if !errors.Is(err, ErrorInvalidCcelDataMinimumLength) {
		t.Fatal("Expected error ErrorInvalidCcelDataMinimumLength")
	}
}

func TestInvalidPcr(t *testing.T) {
	nelEvent := &testNelEvent{
		pcr: 4, // RTMRs should be between 0 and 3
	}

	_, err := parseCcelLength(nelEvent.marshal())
	if !errors.Is(err, ErrorInvalidEventLog) {
		t.Fatal("Expected error ErrorInvalidEventLog")
	}
}

func TestInvalidDigestCount(t *testing.T) {
	nelEvent := &testNelEvent{
		digestCount: 5,
	}

	_, err := parseCcelLength(nelEvent.marshal())
	if !errors.Is(err, ErrorInvalidEventLog) {
		t.Fatal("Expected error ErrorInvalidEventLog")
	}
}

func TestInvalidAlg(t *testing.T) {
	nelEvent := &testNelEvent{
		digestCount: 1,
		alg:         uint16(0xFFFF),
	}

	_, err := parseCcelLength(nelEvent.marshal())
	if !errors.Is(err, ErrorInvalidEventLog) {
		t.Fatal("Expected error ErrorInvalidEventLog")
	}
}

func TestInvalidEventSize(t *testing.T) {
	nelEvent := &testNelEvent{
		digestCount: 1,
		alg:         0x0004,
		eventSize:   0x8001,
	}

	_, err := parseCcelLength(nelEvent.marshal())
	if !errors.Is(err, ErrorInvalidEventLog) {
		t.Fatal("Expected error ErrorInvalidEventLog")
	}
}

func marshalCcelTable(table ccelTable) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, table)
	if err != nil {
		log.Fatalf("Failed to encode ccelTable: %v", err)
	}

	return buf.Bytes()
}

type testNelEvent struct {
	pcr         uint32
	eventType   uint32
	digestCount uint32
	alg         uint16
	digest      [20]byte
	eventSize   uint32
	eventBytes  [32]byte
}

func (evt testNelEvent) marshal() []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, evt)
	if err != nil {
		log.Fatalf("Failed to encode testNelEvent: %v", err)
	}

	return buf.Bytes()
}
