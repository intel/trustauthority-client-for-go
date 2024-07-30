/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package sevsnp

const (
	SevSnpDevPath = "/dev/sev-guest"

	SevSnpGetReportSuccess = 0
	SevSnpGetReportFailed  = -1

	SevSnpIoctlRequestSize   = 0x20
	SevSnpReportUserDataSize = 64
	SevSnpMsgReportSize      = 32 + 672 + 512
	SevSnpMaxReportSize      = 4000
)

type TcbVersion struct {
	Bootloader uint8
	Tee        uint8
	Reserved   [4]uint8
	Snp        uint8
	Microcode  uint8
}

type SignatureStruct struct {
	R        [72]byte
	S        [72]byte
	Reserved [368]byte
}

type AttestationReport struct {
	Version         uint32
	GuestSvn        uint32
	Policy          uint64
	FamilyId        [16]uint8
	ImageId         [16]uint8
	Vmpl            uint32
	SigAlgo         uint32
	CurrentTcb      TcbVersion
	PlatInfo        uint64
	AuthorKeyEnc    uint32
	Reserved2       uint32
	ReportData      [64]uint8
	Measurement     [48]uint8
	HostData        [32]uint8
	IdKeyDigest     [48]uint8
	AuthorKeyDigest [48]uint8
	ReportId        [32]uint8
	ReportIdMa      [32]uint8
	ReportedTcb     TcbVersion
	Reserved3       [24]uint8
	ChipId          [64]uint8
	CommittedTcb    TcbVersion
	CurrentBuild    uint8
	CurrentMinor    uint8
	CurrentMajor    uint8
	Reserved4       uint8
	CommittedBuild  uint8
	CommittedMinor  uint8
	CommittedMajor  uint8
	Reserved5       uint8
	LaunchTcb       TcbVersion
	Reserved6       [168]uint8
	Signature       SignatureStruct
}

type MsgReportResponse struct {
	Status     uint32
	ReportSize uint32
	Reserved   [24]byte
	Report     AttestationReport
}

type SevSnpReportRequest struct {
	UserData [SevSnpReportUserDataSize]byte
	Vmpl     uint32
	Reserved [28]byte
}

type SevSnpReportResponse struct {
	Data [SevSnpMaxReportSize]byte
}

type SevSnpGuestRequestIoctl struct {
	MsgVersion uint8
	ReqData    *SevSnpReportRequest
	RespData   *SevSnpReportResponse
	FwError    uint64
}

const (
	IocNrBits            = 8
	IocTypeBits          = 8
	IocSizeBits          = 14
	IocNrShift           = 0
	IocWrite     uintptr = 1
	IocRead      uintptr = 2
	IocTypeShift         = IocNrShift + IocNrBits
	IocSizeShift         = IocTypeShift + IocTypeBits
	IocDirshift          = IocSizeShift + IocSizeBits
)
