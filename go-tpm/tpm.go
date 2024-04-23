/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"crypto"
	"crypto/x509"
)

type TrustedPlatformModule interface {
	NVRead(nvHandle int) ([]byte, error)
	NVWrite(nvHandle int, data []byte) error
	NVExists(nvHandle int) bool
	NVDefine(nvHandle int, len int) error
	NVDelete(nvHandle int) error
	ReadPublic(handle int) (crypto.PublicKey, []byte, []byte, error)
	GetEKCertificate(nvIndex int) (*x509.Certificate, error)
	GetQuote(akHandle int, nonce []byte, selection ...PcrSelection) ([]byte, []byte, error)
	GetPcrs(selection ...PcrSelection) ([]byte, error)
	HandleExists(handle int) bool
	Close()
}

type TpmDeviceType int

const (
	Linux TpmDeviceType = iota
	MSSIM
)

// PcrSelection is a struct that contains the hash algorithm and the list of PCRs
// that will be included in quotes/pcr data.
type PcrSelection struct {
	Hash crypto.Hash
	Pcrs []int
}
