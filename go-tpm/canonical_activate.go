/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"github.com/canonical/go-tpm2"
	"github.com/pkg/errors"
)

func (tpm *canonicalTpm) ActivateCredential(ekHandle int, akHandle int, credentialBlob []byte, secret []byte) ([]byte, error) {

	// verify the ak handle and create an "akContext" needed for ActivateCredential
	ak := tpm2.Handle(akHandle)
	if ak.Type() != tpm2.HandleTypePersistent {
		return nil, ErrInvalidHandle
	}

	if !tpm.ctx.DoesHandleExist(ak) {
		return nil, ErrHandleDoesNotExist
	}

	akContext, err := tpm.ctx.NewResourceContext(ak)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create resource context for handle 0x%x", akHandle)
	}
	akContext.SetAuthValue(tpm.ownerAuth)

	// verify the ek handle and create an "ekContext" needed for ActivateCredential
	ek := tpm2.Handle(ekHandle)
	if ek.Type() != tpm2.HandleTypePersistent {
		return nil, ErrInvalidHandle
	}

	if !tpm.ctx.DoesHandleExist(ek) {
		return nil, ErrHandleDoesNotExist
	}

	ekContext, err := tpm.ctx.NewResourceContext(ek)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create resource context for handle 0x%x", ekHandle)
	}

	// start a session with endorsement hierarchy policy permissions
	ekAuthSession, err := tpm.ctx.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, err
	}

	_, _, err = tpm.ctx.PolicySecret(tpm.ctx.EndorsementHandleContext(), ekAuthSession, nil, nil, 0, nil, nil)
	if err != nil {
		return nil, err
	}

	decrypted, err := tpm.ctx.ActivateCredential(akContext, ekContext, credentialBlob, secret, nil, ekAuthSession)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}
