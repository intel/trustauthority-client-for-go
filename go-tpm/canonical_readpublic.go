/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"crypto"

	"github.com/canonical/go-tpm2"
	"github.com/pkg/errors"
)

// ReadPublic returns the public key, AK name and qualified name from the
// public handle argument.  It returns an error if  the handle is not persistent
// or does not exist.
func (tpm *canonicalTpm) ReadPublic(handle int) (crypto.PublicKey, []byte, []byte, error) {

	// verify the handle and load a resource context for the handle
	h := tpm2.Handle(handle)
	if h.Type() != tpm2.HandleTypePersistent {
		return nil, nil, nil, ErrInvalidHandle
	}

	if !tpm.ctx.DoesHandleExist(h) {
		return nil, nil, nil, ErrHandleDoesNotExist
	}

	handleContext, err := tpm.ctx.NewResourceContext(h)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "Failed to create resource context for handle %x", handle)
	}

	public, name, qualifiedName, err := tpm.ctx.ReadPublic(handleContext, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	return public.Public(), name, qualifiedName, nil
}

// HandleExists is a utility function that returns true if the handle exists in the TPM.
func (tpm *canonicalTpm) HandleExists(handle int) bool {
	return tpm.ctx.DoesHandleExist(tpm2.Handle(handle))
}
