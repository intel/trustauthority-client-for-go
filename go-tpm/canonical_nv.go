/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"github.com/canonical/go-tpm2"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (tpm *canonicalTpm) NVRead(nvHandle int) ([]byte, error) {

	if nvHandle < minNvHandle || nvHandle > maxNvHandle {
		return nil, ErrHandleOutOfRange
	}

	// Verify that the provided handle is within the range of nv space
	handle := tpm2.Handle(nvHandle)
	if handle.Type() != tpm2.HandleTypeNVIndex {
		return nil, ErrInvalidHandle
	}

	if !tpm.ctx.DoesHandleExist(handle) {
		return nil, ErrorNvIndexDoesNotExist
	}

	// Read the size of the data stored in the specified NVRAM index
	handleContext := tpm2.NewLimitedHandleContext(handle)
	nvPublic, _, err := tpm.ctx.NVReadPublic(handleContext)
	if err != nil {
		return nil, err
	}

	nvContext, err := tpm.ctx.NewResourceContext(tpm2.Handle(handle))
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create resource context for handle %x", handle)
	}

	data, err := tpm.ctx.NVRead(tpm.ctx.OwnerHandleContext(), nvContext, nvPublic.Size, 0, nil, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "Error nvram at handle %x", handle)
	}

	return data, nil
}

func (tpm *canonicalTpm) NVWrite(nvHandle int, data []byte) error {

	if nvHandle < minNvHandle || nvHandle > maxNvHandle {
		return ErrHandleOutOfRange
	}

	if len(data) > maxNvSize {
		return errors.Wrapf(ErrNvSizeExceeded, "Size %d exceeds max %d", len(data), maxNvSize)
	}

	// Verify that the provided handle is within the range of nv space
	handle := tpm2.Handle(nvHandle)
	if handle.Type() != tpm2.HandleTypeNVIndex {
		return ErrInvalidHandle
	}

	// delete the nv index if it already exists
	if !tpm.ctx.DoesHandleExist(handle) {
		return errors.Errorf("NV index %x does not exist", nvHandle)
	}

	nvContext, err := tpm.ctx.NewResourceContext(handle)
	if err != nil {
		return errors.Wrapf(err, "Failed to create resource context at handle %x", handle)
	}
	nvContext.SetAuthValue(tpm.ownerAuth)

	session, err := tpm.ctx.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return err
	}

	err = tpm.ctx.NVWrite(tpm.ctx.OwnerHandleContext(), nvContext, data, 0, session)
	if err != nil {
		return errors.Wrapf(ErrNvWriteFailed, "Index %d: %s", nvHandle, err.Error())
	}

	tpm.ctx.FlushContext(session)

	logrus.Debugf("Successfully wrote %d bytes at NV index %x", len(data), nvHandle)
	return nil
}

func (tpm *canonicalTpm) NVDelete(nvHandle int) error {

	if nvHandle < minNvHandle || nvHandle > maxNvHandle {
		return ErrHandleOutOfRange
	}

	// Verify that the provided handle is within the range of nv space
	handle := tpm2.Handle(nvHandle)
	if handle.Type() != tpm2.HandleTypeNVIndex {
		return ErrInvalidHandle
	}

	// delete the nv index if it already exists
	if !tpm.ctx.DoesHandleExist(handle) {
		return errors.Errorf("Cannot delete non-existent nv index at %x", nvHandle)
	}

	existingCtx, err := tpm.ctx.NewResourceContext(handle)
	if err != nil {
		return errors.Wrapf(err, "Failed to create resource context for handle %x", handle)
	}

	err = tpm.ctx.NVUndefineSpace(tpm.ctx.OwnerHandleContext(), existingCtx, nil)
	if err != nil {
		return errors.Wrapf(ErrNvReleaseFailed, "Index %d: %s", nvHandle, err.Error())
	}

	return nil
}

func (tpm *canonicalTpm) NVDefine(nvHandle int, len int) error {

	if nvHandle < minNvHandle || nvHandle > maxNvHandle {
		return ErrHandleOutOfRange
	}

	// Verify that the provided handle is within the range of nv space
	handle := tpm2.Handle(nvHandle)
	if handle.Type() != tpm2.HandleTypeNVIndex {
		return ErrInvalidHandle
	}

	// delete the nv index if it already exists
	if tpm.ctx.DoesHandleExist(handle) {
		return errors.Errorf("Cannot create an existing nv index %x", nvHandle)
	}

	auth := tpm.ownerAuth

	nvPublic := tpm2.NVPublic{
		Index:      handle,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite,
		AuthPolicy: auth,
		Size:       uint16(len),
	}

	_, err := tpm.ctx.NVDefineSpace(tpm.ctx.OwnerHandleContext(), auth, &nvPublic, nil)
	if err != nil {
		return errors.Wrapf(ErrNvDefineSpaceFailed, "Index %d: %s", nvHandle, err.Error())
	}

	return nil
}

func (tpm *canonicalTpm) NVExists(nvHandle int) bool {

	if nvHandle < minNvHandle || nvHandle > maxNvHandle {
		logrus.Errorf("NV handle %x is out of range", nvHandle)
		return false
	}

	handle := tpm2.Handle(nvHandle)
	if handle.Type() != tpm2.HandleTypeNVIndex {
		logrus.Errorf("Cannot determine if nv ram exists at invalid handle %x", nvHandle)
		return false
	}

	return tpm.ctx.DoesHandleExist(handle)
}
