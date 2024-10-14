/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

// The go-tpm package provides an application level interface to an underlying
// TPM or vTPM device.  It is not intended to be a comprehesive TPM 2.0
// interface and provides a higher level abstraction needed by the Trust
// Authority client.
//
// It exposes a number of TPM functions for getting quotes, reading public keys,
// and reading/writing NV ram.  These are primarily used by the trustauthority-cli.
// It also provides an implementation of the connector.CompositeEvidenceAdapter
// interface which is also used by the trustauthority-cli.
package tpm

import (
	"crypto"
	"crypto/x509"

	"github.com/canonical/go-tpm2"
	"github.com/pkg/errors"
)

type TrustedPlatformModule interface {
	// CreateEK persists a new Endorsement Key in the endorsement hierarchy at the specified
	// handle. It fails if the handle is not within range of persistent handles or, if the
	// handle already exists (it should be deleted using tpm2-evictcontrol -c {handle}).
	//
	// The EK is used to perform decryption when interacting ITA during AK provisioning.
	CreateEK(ekHandle int) error

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
	TpmDeviceUnknown TpmDeviceType = iota
	TpmDeviceLinux
	TpmDeviceMSSIM

	unknownString = "unknown"
	mssimString   = "mssim"
	linuxString   = "linux"
)

func ParseTpmDeviceType(s string) (TpmDeviceType, error) {
	switch s {
	case linuxString:
		return TpmDeviceLinux, nil
	case mssimString:
		return TpmDeviceMSSIM, nil
	default:
		return TpmDeviceUnknown, errors.Errorf("Unknown TPM device type: %s", s)
	}
}

func (t TpmDeviceType) String() string {
	switch t {
	case TpmDeviceUnknown:
		return unknownString
	case TpmDeviceLinux:
		return linuxString
	case TpmDeviceMSSIM:
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

// Close closes the TPM.
func (tpm *trustedPlatformModule) Close() {
	if tpm.ctx != nil {
		tpm.ctx.Close()
	}
}

// The internal structure for canonical TPM implementation
type trustedPlatformModule struct {
	ctx        *tpm2.TPMContext
	deviceType TpmDeviceType
	ownerAuth  []byte
}
