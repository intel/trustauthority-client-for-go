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

// TpmFactory is an interface for creating TrustedPlatformModule instances.
type TpmFactory interface {
	New(deviceType TpmDeviceType, ownerAuth string) (TrustedPlatformModule, error)
}

// Default TPM factory that creates a TrustedPlatformModule implementation
// suitable for use with a physical/linux device or TPM simulator.
func NewTpmFactory() TpmFactory {
	return &tpmFactory{}
}

type tpmFactory struct{}

// New creates an instance of a TrustedPlatformModule.
func (f *tpmFactory) New(deviceType TpmDeviceType, ownerAuth string) (TrustedPlatformModule, error) {
	var err error

	// Fill in defaults that may be overriden by options below
	tpm := &trustedPlatformModule{
		deviceType: deviceType,
	}

	if ownerAuth == "" {
		tpm.ownerAuth = []byte{}
	} else {
		tpm.ownerAuth = []byte(ownerAuth)
	}

	var device tpm2.TPMDevice
	if tpm.deviceType == TpmDeviceLinux {
		defaultDevice, err := linux.DefaultTPM2Device()
		if err != nil {
			return nil, err
		}

		device, err = defaultDevice.ResourceManagedDevice()
		if err != nil {
			return nil, err
		}
	} else if tpm.deviceType == TpmDeviceMSSIM {
		device = mssim.NewLocalDevice(mssim.DefaultPort)
	}

	tpm.ctx, err = tpm2.OpenTPMDevice(device)
	if err != nil {
		return nil, err
	}

	tpm.ctx.OwnerHandleContext().SetAuthValue(tpm.ownerAuth)

	return tpm, nil
}
