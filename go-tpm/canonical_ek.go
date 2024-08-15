/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/sirupsen/logrus"
)

func (tpm *canonicalTpm) CreateEK(ekHandle int) error {

	// Verify the type and handle and make sure it doesn't already exist
	handle := tpm2.Handle(ekHandle)
	if handle.Type() != tpm2.HandleTypePersistent {
		return ErrInvalidHandle
	}

	if tpm.ctx.DoesHandleExist(handle) {
		return ErrExistingHandle
	}

	// create a public key template and create the primary (e) key
	ekTemplate := objectutil.NewRSAStorageKeyTemplate()
	ekTemplate.AuthPolicy = defaultAuthPolicySha256
	ekTemplate.Attrs &= ^(tpm2.AttrUserWithAuth)
	ekTemplate.Attrs |= tpm2.AttrAdminWithPolicy
	ekTemplate.Unique = &tpm2.PublicIDU{
		RSA: make([]byte, 256),
	}

	primary, _, _, _, _, err := tpm.ctx.CreatePrimary(tpm.ctx.EndorsementHandleContext(), nil, ekTemplate, nil, nil, nil)
	if err != nil {
		return err
	}

	// persist the ek to the specfied handle
	_, err = tpm.ctx.EvictControl(tpm.ctx.OwnerHandleContext(), primary, handle, nil)
	if err != nil {
		return err
	}

	defer tpm.ctx.FlushContext(primary)

	logrus.Infof("Successfully created EK at handle %x", ekHandle)
	return nil
}
