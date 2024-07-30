//go:build !test

/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package sevsnp

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/intel/trustauthority-client/go-connector"
)

func IOC(dir, t, nr, size uintptr) uintptr {
	return (dir << IocDirshift) |
		(t << IocTypeShift) |
		(nr << IocNrShift) |
		(size << IocSizeShift)
}

func IOWR(t, nr, size uintptr) uintptr {
	return IOC(IocRead|IocWrite, t, nr, size)
}

func SevSnpCmdGetReportIO() uintptr {
	return IOWR('S', 0x0, SevSnpIoctlRequestSize)
}

// CollectEvidence is used to get sevsnp report using IOCTL driver interface
func (adapter *sevsnpAdapter) CollectEvidence(nonce []byte) (*connector.Evidence, error) {

	messageHash512 := sha512.Sum512(append(nonce, adapter.uData[:]...))
	var sevsnpRequest SevSnpReportRequest
	var sevsnpResponse SevSnpReportResponse

	var sevsnpRequestIoctl SevSnpGuestRequestIoctl
	copy(sevsnpRequest.UserData[:], []byte(messageHash512[:]))
	sevsnpRequest.Vmpl = 0

	sevsnpRequestIoctl.MsgVersion = 1
	sevsnpRequestIoctl.ReqData = &sevsnpRequest
	sevsnpRequestIoctl.RespData = &sevsnpResponse
	mode := uint32(0600)

	fd, err := syscall.Open(SevSnpDevPath, syscall.O_RDWR, mode)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)

	cmd := SevSnpCmdGetReportIO()
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&sevsnpRequestIoctl)))
	if errno != 0 {
		return nil, syscall.Errno(errno)
	}

	data := sevsnpRequestIoctl.RespData.Data[32:SevSnpMsgReportSize]
	fmt.Println(base64.StdEncoding.EncodeToString(data))

	return &connector.Evidence{
		Type:     1,
		Evidence: data,
		UserData: adapter.uData,
	}, nil
}
