/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"crypto"
	"crypto/x509"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/mssim"
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

// TpmOption for opening a connection/session with the TPM.
type TpmOption func(*trustedPlatformModule) error

// New creates an instance of a TrustedPlatformModule.
func New(options ...TpmOption) (TrustedPlatformModule, error) {
	var err error

	// Fill in defaults that may be overriden by options below
	tpm := &trustedPlatformModule{
		deviceType: Linux,
		ownerAuth:  []byte{},
	}

	for _, option := range options {
		if err := option(tpm); err != nil {
			return nil, err
		}
	}

	var device tpm2.TPMDevice
	if tpm.deviceType == Linux {
		defaultDevice, err := linux.DefaultTPM2Device()
		if err != nil {
			return nil, err
		}

		device, err = defaultDevice.ResourceManagedDevice()
		if err != nil {
			return nil, err
		}
	} else if tpm.deviceType == MSSIM {
		device = mssim.NewLocalDevice(mssim.DefaultPort)
	}

	tpm.ctx, err = tpm2.OpenTPMDevice(device)
	if err != nil {
		return nil, err
	}

	return tpm, nil
}

// WithOwnerAuth specifies the owner password used to communicate
// with the TPM.  By default, the empty string is used.
func WithTpmOwnerAuth(ownerAuth string) TpmOption {
	return func(ctf *trustedPlatformModule) error {
		if ownerAuth == "" {
			ctf.ownerAuth = []byte{}
		} else {
			ctf.ownerAuth = []byte(ownerAuth)
		}

		return nil
	}
}

// WithDeviceType specifies the type of TPM device to use.  By default,
// the Linux device is used (/dev/tpmrm0).
func WithTpmDeviceType(deviceType TpmDeviceType) TpmOption {
	return func(ctf *trustedPlatformModule) error {
		ctf.deviceType = deviceType
		return nil
	}
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
