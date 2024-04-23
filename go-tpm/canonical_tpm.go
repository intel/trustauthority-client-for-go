/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/mssim"
)

// TpmOption for opening a connection/session with the TPM.
type TpmOption func(*canonicalTpm) error

// New creates an instance of a TrustedPlatformModule.
func New(options ...TpmOption) (TrustedPlatformModule, error) {
	var err error

	// Fill in defaults that may be overriden by options below
	tpm := &canonicalTpm{
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
	return func(ctf *canonicalTpm) error {
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
	return func(ctf *canonicalTpm) error {
		ctf.deviceType = deviceType
		return nil
	}
}

// Close closes the TPM.
func (tpm *canonicalTpm) Close() {
	if tpm.ctx != nil {
		tpm.ctx.Close()
	}
}

// The internal structure for canonical TPM implementation
type canonicalTpm struct {
	ctx        *tpm2.TPMContext
	deviceType TpmDeviceType
	ownerAuth  []byte
}
