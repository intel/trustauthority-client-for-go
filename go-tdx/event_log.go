/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

// These variables can be used by integrators to override the default
// behavior of event-log parsing.  By default, the file paths are empty
// and the Application will attempt to read event logs from /sys/firmware.
//
// However, in some environments (ex. embedded linux), /sys/firmware may not
// be available.  In these scenarios, an integrator can compile the application
// with go build flags and specify a file containing TCG event-log data.
// For example...
//    env CGO_CFLAGS_ALLOW="-f.*" go build -ldflags "-X github.com/go-module/eventlog.uefiEventLogFile=/tmp/myuefieventlogs.bin"
var (
	uefiEventLogFile = ""
)

const (
	TdelFileLength    = 56
	TdelSignature     = "TDEL"
	AcpiTablePath     = "/sys/firmware/acpi/tables/"
	AcpiTableDataPath = "/sys/firmware/acpi/tables/data/"
	TdelPath          = AcpiTablePath + TdelSignature
	TdelDataPath      = AcpiTableDataPath + TdelSignature
)

const (
	Uint8Size            = 1
	Uint16Size           = 2
	Uint32Size           = 4
	Uint64Size           = 8
	ExtDataElementOffset = 92
	// Uefi Event Info
	UefiBaseOffset = 48
	UefiSizeOffset = 40
	// Event types
	Event80000001 = 0x80000001
	Event80000002 = 0x80000002
	Event80000007 = 0x80000007
	Event8000000A = 0x8000000A
	Event8000000B = 0x8000000B
	Event8000000C = 0x8000000C
	Event80000010 = 0x80000010
	Event800000E0 = 0x800000E0
	Event00000007 = 0x00000007
	Event00000001 = 0x00000001
	Event00000003 = 0x00000003
	Event00000005 = 0x00000005
	Event0000000A = 0x0000000A
	Event0000000C = 0x0000000C
	Event00000012 = 0x00000012
	Event00000010 = 0x00000010
	Event00000011 = 0x00000011
	EV_IPL        = 0x0000000D
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

// EventNameList - define map for event name
var eventNameList = map[uint32]string{
	0x00000000: "EV_PREBOOT_CERT",
	0x00000001: "EV_POST_CODE",
	0x00000002: "EV_UNUSED",
	0x00000003: "EV_NO_ACTION",
	0x00000004: "EV_SEPARATOR",
	0x00000005: "EV_ACTION",
	0x00000006: "EV_EVENT_TAG",
	0x00000007: "EV_S_CRTM_CONTENTS",
	0x00000008: "EV_S_CRTM_VERSION",
	0x00000009: "EV_CPU_MICROCODE",
	0x0000000A: "EV_PLATFORM_CONFIG_FLAGS",
	0x0000000B: "EV_TABLE_OF_DEVICES",
	0x0000000C: "EV_COMPACT_HASH",
	0x0000000D: "EV_IPL",
	0x0000000E: "EV_IPL_PARTITION_DATA",
	0x0000000F: "EV_NONHOST_CODE",
	0x00000010: "EV_NONHOST_CONFIG",
	0x00000011: "EV_NONHOST_INFO",
	0x00000012: "EV_OMIT_BOOT_DEVICE_EVENTS",
	0x80000000: "EV_EFI_EVENT_BASE",
	0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG",
	0x80000002: "EV_EFI_VARIABLE_BOOT",
	0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION",
	0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
	0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER",
	0x80000006: "EV_EFI_GPT_EVENT",
	0x80000007: "EV_EFI_ACTION",
	0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
	0x80000009: "EV_EFI_HANDOFF_TABLES",
	0x8000000A: "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
	0x8000000B: "EV_EFI_HANDOFF_TABLES2",
	0x8000000C: "EV_EFI_VARIABLE_BOOT2",
	0x80000010: "EV_EFI_HCRTM_EVENT",
	0x800000E0: "EV_EFI_VARIABLE_AUTHORITY",
	0x800000E1: "EV_EFI_SPDM_FIRMWARE_BLOB",
	0x800000E2: "EV_EFI_SPDM_FIRMWARE_CONFIG",
}

// RtmrEventLog structure is used to hold complete event log info
type RtmrEventLog struct {
	Rtmr       RtmrData    `json:"rtmr"`
	RtmrEvents []RtmrEvent `json:"rtmr_events"`
}

// RtmrData structure is used to hold rtmr info
type RtmrData struct {
	Index uint32 `json:"index"`
	Bank  string `json:"bank"`
}

// RtmrEvent structure is used to hold RTMR Event Info
type RtmrEvent struct {
	TypeID      string   `json:"type_id"`
	TypeName    string   `json:"type_name,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Measurement string   `json:"measurement"`
}

// TcgPcrEventV2 structure represents TCG_PCR_EVENT2 of Intel TXT spec rev16.2
type tcgPcrEventV2 struct {
	PcrIndex  uint32
	EventType uint32
	Digest    tpmlDigestValue
	EventSize uint32
	Event     []uint8
}

// TpmlDigestValue structure represents TPML_DIGEST_VALUES of Intel TXT spec rev16.2
type tpmlDigestValue struct {
	Count   uint32
	Digests []tpmtHA
}

// TpmtHA structure represents TPMT_HA of Intel TXT spec rev16.2
type tpmtHA struct {
	HashAlg    uint16
	DigestData []byte
}

// TcgPcrEventV1 structure represents TCG_PCR_EVENT of Intel TXT spec rev16.2
type tcgPcrEventV1 struct {
	PcrIndex  uint32
	EventType uint32
	Digest    [20]byte
	EventSize uint32
	Event     []uint8
}

// UefiGUID structure represents UEFI_GUID of TCG PC Client Platform Firmware Profile spec rev22
type uefiGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]uint8
}

// UefiVariableData structure represents UEFI_GUID of TCG PC Client Platform Firmware Profile spec rev22
type uefiVariableData struct {
	VariableName       uefiGUID
	UnicodeNameLength  uint64
	VariableDataLength uint64
	UnicodeName        []uint16
	VariableData       []int8 // Driver or platform-specific data
}
