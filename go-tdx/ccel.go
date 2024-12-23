/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tdx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	CcelFileLength    = 56
	CcelSignature     = "CCEL"
	CcelType          = 2
	CcelSubType       = 0
	AcpiTablePath     = "/sys/firmware/acpi/tables/"
	AcpiTableDataPath = "/sys/firmware/acpi/tables/data/"
	CcelPath          = AcpiTablePath + CcelSignature
	CcelDataPath      = AcpiTableDataPath + CcelSignature

	// SHA Types
	SHA256  = "SHA256"
	SHA384  = "SHA384"
	SHA512  = "SHA512"
	SM3_256 = "SM3_256"

	// Algorithm Types
	AlgSHA256        = 0xb
	AlgSHA384        = 0xc
	AlgSHA512        = 0xd
	AlgSM3_256       = 0x12
	NullUnicodePoint = "\u0000"
)

// https://github.com/torvalds/linux/blob/cdd30ebb1b9f36159d66f088b61aee264e649d7a/include/acpi/actbl.h#L68
// struct acpi_table_header {
// 	char signature[ACPI_NAMESEG_SIZE];	/* ASCII table signature */
// 	u32 length;		/* Length of table in bytes, including this header */
// 	u8 revision;		/* ACPI Specification minor version number */
// 	u8 checksum;		/* To make sum of entire table == 0 */
// 	char oem_id[ACPI_OEM_ID_SIZE];	/* ASCII OEM identification */
// 	char oem_table_id[ACPI_OEM_TABLE_ID_SIZE];	/* ASCII OEM table identification */
// 	u32 oem_revision;	/* OEM revision number */
// 	char asl_compiler_id[ACPI_NAMESEG_SIZE];	/* ASCII ASL compiler vendor ID */
// 	u32 asl_compiler_revision;	/* ASL compiler version */
// };

type AcpiTableHeader struct {
	Signature           [4]byte
	Length              uint32
	Revision            uint8
	Checksum            uint8
	OemId               [6]byte
	OemTableId          [8]byte
	OemRevision         uint32
	AslCompilerId       [4]byte
	AslCompilerRevision uint32
}

// https://github.com/torvalds/linux/blob/cdd30ebb1b9f36159d66f088b61aee264e649d7a/include/acpi/actbl2.h#L442
// struct acpi_table_ccel {
// 	struct acpi_table_header header;	/* Common ACPI table header */
// 	u8 CCtype;
// 	u8 Ccsub_type;
// 	u16 reserved;
// 	u64 log_area_minimum_length;
// 	u64 log_area_start_address;
// };

type ccelTable struct {
	AcpiTableHeader
	CCtype               uint8
	Ccsub_type           uint8
	Reserved             uint16
	LogAreaMinimumLength uint64
	LogAreaStartAddress  uint64
}

var (
	ErrorInvalidCcelTableSignature    = errors.New("invalid CCEL table signature")
	ErrorInvalidCcelTableLength       = errors.New("invalid CCEL table length")
	ErrorInvalidCcelTableType         = errors.New("invalid CCEL table type")
	ErrorInvalidCcelTableSubType      = errors.New("invalid CCEL table sub type")
	ErrorInvalidCcelDataMinimumLength = errors.New("invalid CCEL data minimum length")
)

func (ccel *ccelTable) validate(tableLen int) error {
	// verify the table signature is CCEL
	if string(ccel.AcpiTableHeader.Signature[:]) != CcelSignature {
		return fmt.Errorf("Signature %s is invalid: %w", string(ccel.AcpiTableHeader.Signature[:]), ErrorInvalidCcelTableSignature)
	}

	// verify the table length matches the size of the table
	if int(ccel.AcpiTableHeader.Length) != tableLen {
		return ErrorInvalidCcelTableLength
	}

	// verify the type and subtype
	if ccel.CCtype != CcelType {
		return ErrorInvalidCcelTableType
	}
	if ccel.Ccsub_type != CcelSubType {
		return ErrorInvalidCcelTableSubType
	}

	return nil
}

func parseCcelTable(data []byte) (*ccelTable, error) {
	c := ccelTable{}

	reader := bytes.NewReader(data)

	_, err := reader.Read(c.Signature[:])
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.LittleEndian, &c.Length)
	if err != nil {
		return nil, err
	}

	c.Revision, err = reader.ReadByte()
	if err != nil {
		return nil, err
	}

	c.Checksum, err = reader.ReadByte()
	if err != nil {
		return nil, err
	}

	_, err = reader.Read(c.OemId[:])
	if err != nil {
		return nil, err
	}

	_, err = reader.Read(c.OemTableId[:])
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.LittleEndian, &c.OemRevision)
	if err != nil {
		return nil, err
	}

	_, err = reader.Read(c.AslCompilerId[:])
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.LittleEndian, &c.AslCompilerRevision)
	if err != nil {
		return nil, err
	}

	c.CCtype, err = reader.ReadByte()
	if err != nil {
		return nil, err
	}

	c.Ccsub_type, err = reader.ReadByte()
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.LittleEndian, &c.Reserved)
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.LittleEndian, &c.LogAreaMinimumLength)
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.LittleEndian, &c.LogAreaStartAddress)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

func readCcelTable(ccelTablePath string) (*ccelTable, error) {
	ccelTableBytes, err := os.ReadFile(ccelTablePath)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading CCEL table from %s", ccelTablePath)
	}

	ccelTable, err := parseCcelTable(ccelTableBytes)
	if err != nil {
		return nil, err
	}

	err = ccelTable.validate(len(ccelTableBytes))
	if err != nil {
		return nil, err
	}

	return ccelTable, nil
}

// readCcelData performs error checking of the acpi CCEL table to verify
// the underlying host is TDX capable.  If so, it reads the CCEL raw
// data and returns its contents back to the caller.
func readCcelData(ccelTable *ccelTable, ccelDataPath string) ([]byte, error) {
	// read the CCEL data and verify it's length against the table header
	ccelData, err := os.ReadFile(ccelDataPath)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading CCEL data from %s", ccelDataPath)
	}
	if uint64(len(ccelData)) < ccelTable.LogAreaMinimumLength {
		return nil, ErrorInvalidCcelDataMinimumLength
	}

	logrus.Debugf("Successfully read %d bytes from %s", len(ccelData), ccelDataPath)
	return ccelData, nil
}
