/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/pkg/errors"
)

func (tpm *trustedPlatformModule) CreateAK(akHandle int, ekHandle int) error {

	// make sure the akHandle is within range, a valid persistant handle and it DOES NOT exist
	ak := tpm2.Handle(akHandle)
	if ak.Type() != tpm2.HandleTypePersistent {
		return ErrHandleOutOfRange
	}

	if tpm.ctx.DoesHandleExist(ak) {
		return ErrExistingHandle
	}

	// make sure the ekHandle is a valid persistant handle and it DOES exist
	ek := tpm2.Handle(ekHandle)
	if ek.Type() != tpm2.HandleTypePersistent {
		return ErrInvalidHandle
	}

	if !tpm.ctx.DoesHandleExist(ek) {
		return ErrHandleDoesNotExist
	}

	// create a new "resource context" for the EK handle
	ekContext, err := tpm.ctx.NewResourceContext(ek)
	if err != nil {
		return errors.Wrapf(err, "Failed to create resource context for EK at handle 0x%x", ekHandle)
	}

	// start an auth policy session in the endorsement hierarchy
	session, err := tpm.ctx.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return err
	}
	session.SetAttrs(tpm2.AttrContinueSession)

	_, _, err = tpm.ctx.PolicySecret(tpm.ctx.EndorsementHandleContext(), session, nil, nil, 0, nil, nil)
	if err != nil {
		return err
	}

	// create a public key template and key
	options := []objectutil.PublicTemplateOption{objectutil.WithoutDictionaryAttackProtection()}
	akTemplate := objectutil.NewRSAAttestationKeyTemplate(options...)
	private, public, _, _, _, err := tpm.ctx.Create(ekContext, nil, akTemplate, nil, nil, session)
	if err != nil {
		return err
	}

	err = tpm.ctx.FlushContext(session)
	if err != nil {
		return err
	}

	// start a new session and load the key created above
	session, err = tpm.ctx.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return err
	}

	_, _, err = tpm.ctx.PolicySecret(tpm.ctx.EndorsementHandleContext(), session, nil, nil, 0, nil, nil)
	if err != nil {
		return err
	}

	loadContext, err := tpm.ctx.Load(ekContext, private, public, session, nil)
	if err != nil {
		return err
	}

	// persist the ak to the specified handle
	_, err = tpm.ctx.EvictControl(tpm.ctx.OwnerHandleContext(), loadContext, ak, nil, nil)
	if err != nil {
		return err
	}

	return nil
}

func (tpm *trustedPlatformModule) CreateAkFromTemplate(akHandle int, akTemplate []byte) error {

	// make sure the akHandle is within range, a valid persistant handle and it DOES NOT exist
	handle := tpm2.Handle(akHandle)
	if handle.Type() != tpm2.HandleTypePersistent {
		return ErrHandleOutOfRange
	}

	if tpm.ctx.DoesHandleExist(handle) {
		return ErrExistingHandle
	}

	template := tpm2.Public{}
	_, err := mu.UnmarshalFromBytes(akTemplate, &template)
	if err != nil {
		return errors.Wrapf(err, "Failed to unmarshal TPMT_PUBLIC bytes")
	}

	primary, _, _, _, _, err := tpm.ctx.CreatePrimary(tpm.ctx.EndorsementHandleContext(), nil, &template, nil, nil, nil)
	if err != nil {
		return err
	}

	// persist the ak to the specfied handle
	_, err = tpm.ctx.EvictControl(tpm.ctx.OwnerHandleContext(), primary, handle, nil)
	if err != nil {
		return err
	}

	err = tpm.ctx.FlushContext(primary)
	if err != nil {
		return err
	}

	return nil
}
