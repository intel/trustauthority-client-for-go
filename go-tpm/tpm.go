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
	// NVRead reads the bytes from the specified nv index/handle.  It returns an
	// error if the handle is not within the range of valid nv ram or if the index
	// does not exist.
	NVRead(nvHandle int) ([]byte, error)

	// NVWRite writes bytes to the specified nv handle/index.  It returns an
	// error if the handle is not within the range of valid nv ram or if the index
	// does not exist.
	NVWrite(nvHandle int, data []byte) error

	// NVExists checks if the specified nv handle/index exists. It returns false if
	// the handle is not within the range of valid nv ram or if the index does not exist.
	NVExists(nvHandle int) bool

	// NVDefine creates a new nv index with the specified handle and size.  It returns
	// an error if the handle is not within the range of valid nv indexes.
	NVDefine(nvHandle int, len int) error

	// NVDelete deletes the specified nv handle/index.  It returns an error if the
	// handle is not within the range of valid nv ram or if the index does not exist.
	NVDelete(nvHandle int) error

	// ReadPublic returns the public key, TPMT Public bytes and qualified name bytes from the
	// public handle argument.  It returns an error if  the handle is not persistent
	// or does not exist.
	ReadPublic(handle int) (crypto.PublicKey, []byte, []byte, error)

	// GetEKCertificate is a utility function that reads NV ram at the specified
	// index and parses its contents into an x509 certificate
	GetEKCertificate(nvIndex int) (*x509.Certificate, error)

	// GetQuote returns a TPM quote for the given nonce using the specified AK handle.  Rturns
	// an error if the akHandle is invalid or does not exist.    If 'selection'
	// is not provided, then all sha256 banks will be included in the quote.
	GetQuote(akHandle int, nonce []byte, selection ...PcrSelection) ([]byte, []byte, error)

	// GetPcrs returns the "flattened", concatenated, contiguous PCR measurements
	// for SHA-256 banks 0-23 (in index order).  This is similar to the pcr values
	// returned in tpm2_quote when '-F values' options are provided.  If 'selection'
	// is not provided, then all sha256 banks are included in the results.
	GetPcrs(selection ...PcrSelection) ([]byte, error)

	// HandleExists is a utility function that returns true if the handle exists in the TPM.
	HandleExists(handle int) bool

	// Close closes the TPM.
	Close()
}

type TpmDeviceType int

const (
	Linux TpmDeviceType = iota
	MSSIM

	mssimString = "mssim"
	linuxString = "linux"
)

func ParseTpmDeviceType(s string) TpmDeviceType {
	switch s {
	case linuxString:
		return Linux
	case mssimString:
		return MSSIM
	default:
		panic("unknown TpmDeviceType")
	}
}

func (t TpmDeviceType) String() string {
	switch t {
	case Linux:
		return linuxString
	case MSSIM:
		return mssimString
	default:
		panic("unknown TpmDeviceType")
	}
}

// PcrSelection is a struct that contains the hash algorithm and the list of PCRs
// that will be included in quotes/pcr data.
type PcrSelection struct {
	Hash crypto.Hash
	Pcrs []int
}
