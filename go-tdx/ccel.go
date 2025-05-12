/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tdx

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	ccelSignature  = "CCEL"
	ccelType       = 2
	ccelSubType    = 0
	maxEventLength = 0x8000 // assume event will not exceed 8k (the event log can contain cert chains)
)

var (
	ErrorCcelTableNotFound            = errors.New("the confidential-computing-event-log (CCEL) acpi table is not present on this computer")
	ErrorCcelDataNotFound             = errors.New("the confidential-computing-event-log (CCEL) acpi data is not present on this computer")
	ErrorAcpiReadFailure              = errors.New("failed to read the ACPI table")
	ErrorInvalidCcelTableSignature    = errors.New("invalid CCEL table signature")
	ErrorInvalidCcelTableLength       = errors.New("invalid CCEL table length")
	ErrorInvalidCcelTableType         = errors.New("invalid CCEL table type")
	ErrorInvalidCcelTableSubType      = errors.New("invalid CCEL table sub type")
	ErrorInvalidCcelDataMinimumLength = errors.New("invalid CCEL data minimum length")
	ErrorInvalidEventLog              = errors.New("invalid event log format")

	// these private, default paths are declared as variables so they
	// can be overridden in unit tests
	acpiPath      = "/sys/firmware/acpi/tables/"
	ccelTablePath = acpiPath + ccelSignature
	ccelDataPath  = acpiPath + "data/" + ccelSignature
)

// GetCcel returns the raw TCG 2.0 "NEL" data from a TDX host's ACPI tables (at
// /sys/firmware/acpi/tables/data/CCEL).  An error is returned if the host does not
// have the ACPI files (i.e., it is not a TDX host, insufficient permissions, etc.).
// It also attempts to verify the correctness of the ACPI "table" data (ex. signature,
// type/subtype, length) and the events container in the log (i.e., to expose errors
// earlier on the client as opposed to later in the backend).
func GetCcel() ([]byte, error) {
	return getCcel(ccelTablePath, ccelDataPath)
}

func getCcel(ccelTablePath, ccelDataPath string) ([]byte, error) {
	tableBytes, err := os.ReadFile(ccelTablePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrorCcelTableNotFound, err)
	}

	dataBytes, err := os.ReadFile(ccelDataPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrorCcelDataNotFound, err)
	}

	err = validateCcelData(tableBytes, dataBytes)
	if err != nil {
		return nil, err
	}

	// parse the TCG 2.0 NEL to truncate trailing 0xFF bytes
	ccelLength, err := parseCcelLength(dataBytes)
	if err != nil {
		return nil, err
	}

	return dataBytes[:ccelLength], nil
}

func validateCcelData(tableBytes, dataBytes []byte) error {
	var table ccelTable
	err := binary.Read(bytes.NewReader(tableBytes), binary.LittleEndian, &table)
	if err != nil {
		return fmt.Errorf("%v: %w", err, ErrorAcpiReadFailure)
	}

	// verify the table signature is CCEL
	if string(table.acpiTableHeader.Signature[:]) != ccelSignature {
		return ErrorInvalidCcelTableSignature
	}

	// verify the table length matches the size of the table
	if int(table.acpiTableHeader.Length) != len(tableBytes) {
		return ErrorInvalidCcelTableLength
	}

	// verify the type and subtype
	if table.CCtype != ccelType {
		return ErrorInvalidCcelTableType
	}
	if table.Ccsub_type != ccelSubType {
		return ErrorInvalidCcelTableSubType
	}

	// verify the CCEL data is not shorter than the table's minimum length
	if uint64(len(dataBytes)) < table.LogAreaMinimumLength {
		return fmt.Errorf("The length of the CCEL data (0x%x) was less than the minimum length (0x%x) : %w", len(dataBytes), table.LogAreaMinimumLength, ErrorInvalidCcelDataMinimumLength)
	}

	return nil
}

// parseCcelLength iterates over the list of TCG 2.0 events contained
// in ccelBytes and returns the position in the array at the end of
// the last event.  Invalid event data (i.e., that is not TCG 2.0) will result
// in errors.
func parseCcelLength(ccelBytes []byte) (int64, error) {
	reader := bytes.NewReader(ccelBytes)
	tmpInt32 := uint32(0)

	for {
		// read RTMR index
		err := binary.Read(reader, binary.LittleEndian, &tmpInt32)
		if err != nil {
			if err == io.EOF {
				break
			}

			return 0, fmt.Errorf("%w: failed to read rtmr value %v", ErrorInvalidEventLog, err)
		}

		if tmpInt32 == 0xffffffff {
			break // 0xFFFFFFF indicates end of event log
		}

		// check for valid RTMR values (there are only 4)
		if tmpInt32 > 3 {
			return 0, fmt.Errorf("%w: invalid rtmr value", ErrorInvalidEventLog)
		}

		// read event type
		err = binary.Read(reader, binary.LittleEndian, &tmpInt32)
		if err != nil {
			return 0, fmt.Errorf("%w: failed to read event type %v", ErrorInvalidEventLog, err)
		}

		// number of digests in event
		err = binary.Read(reader, binary.LittleEndian, &tmpInt32)
		if err != nil {
			return 0, fmt.Errorf("%w: failed to read digest count %v", ErrorInvalidEventLog, err)
		}

		if tmpInt32 > 4 { // assume 4 max (sha1, sha256, sha384, sha512)
			return 0, fmt.Errorf("%w: invalid digest count %d", ErrorInvalidEventLog, tmpInt32)
		}

		for i := 0; i < int(tmpInt32); i++ {
			// digest algorithm
			alg := uint16(0)
			err = binary.Read(reader, binary.LittleEndian, &alg)
			if err != nil {
				return 0, fmt.Errorf("%w: failed to read digest algorithm %v", ErrorInvalidEventLog, err)
			}

			var h crypto.Hash
			switch alg {
			case 0x4:
				h = crypto.SHA1
			case 0xB:
				h = crypto.SHA256
			case 0xC:
				h = crypto.SHA384
			case 0xD:
				h = crypto.SHA512
			default:
				return 0, fmt.Errorf("%w: unsupported digest algorithm %d", ErrorInvalidEventLog, alg)
			}

			// skip the length of the digest
			_, err := reader.Seek(int64(h.Size()), io.SeekCurrent)
			if err != nil {
				return 0, fmt.Errorf("%w: failed to read digest bytes %v", ErrorInvalidEventLog, err)
			}
		}

		// read event size
		err = binary.Read(reader, binary.LittleEndian, &tmpInt32)
		if err != nil {
			return 0, fmt.Errorf("%w: failed to read event size %v", ErrorInvalidEventLog, err)
		}

		if tmpInt32 < 0 || tmpInt32 > maxEventLength {
			return 0, fmt.Errorf("%w: event entry with size %d exceeded maximum size %d", ErrorInvalidEventLog, tmpInt32, maxEventLength)
		}

		// skip the length of the event data
		_, err = reader.Seek(int64(tmpInt32), io.SeekCurrent)
		if err != nil {
			return 0, fmt.Errorf("%w: failed to read event bytes %v", ErrorInvalidEventLog, err)
		}
	}

	offset, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}

	return offset, nil
}

// https://github.com/torvalds/linux/blob/cdd30ebb1b9f36159d66f088b61aee264e649d7a/include/acpi/actbl.h#L68
//
//	struct acpi_table_header {
//		char signature[ACPI_NAMESEG_SIZE];	/* ASCII table signature */
//		u32 length;		/* Length of table in bytes, including this header */
//		u8 revision;		/* ACPI Specification minor version number */
//		u8 checksum;		/* To make sum of entire table == 0 */
//		char oem_id[ACPI_OEM_ID_SIZE];	/* ASCII OEM identification */
//		char oem_table_id[ACPI_OEM_TABLE_ID_SIZE];	/* ASCII OEM table identification */
//		u32 oem_revision;	/* OEM revision number */
//		char asl_compiler_id[ACPI_NAMESEG_SIZE];	/* ASCII ASL compiler vendor ID */
//		u32 asl_compiler_revision;	/* ASL compiler version */
//	};
type acpiTableHeader struct {
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
//
//	struct acpi_table_ccel {
//		struct acpi_table_header header;	/* Common ACPI table header */
//		u8 CCtype;
//		u8 Ccsub_type;
//		u16 reserved;
//		u64 log_area_minimum_length;
//		u64 log_area_start_address;
//	};
type ccelTable struct {
	acpiTableHeader
	CCtype               uint8
	Ccsub_type           uint8
	Reserved             uint16
	LogAreaMinimumLength uint64
	LogAreaStartAddress  uint64
}
