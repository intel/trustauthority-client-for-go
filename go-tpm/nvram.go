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

func (tpm *trustedPlatformModule) NVRead(nvHandle int) ([]byte, error) {

	// Verify that the provided handle is within the range of nv space
	if nvHandle < minNvHandle || nvHandle > maxNvHandle {
		return nil, ErrHandleOutOfRange
	}

	handle := tpm2.Handle(nvHandle)
	if !tpm.ctx.DoesHandleExist(handle) {
		return nil, ErrorNvIndexDoesNotExist
	}

	// Read the size of the data stored in the specified NVRAM index
	handleContext := tpm2.NewHandleContext(handle)
	nvPublic, _, err := tpm.ctx.NVReadPublic(handleContext)
	if err != nil {
		return nil, err
	}

	nvContext, err := tpm.ctx.NewResourceContext(tpm2.Handle(handle))
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create resource context for handle 0x%x", handle)
	}

	data, err := tpm.ctx.NVRead(tpm.ctx.OwnerHandleContext(), nvContext, nvPublic.Size, 0, nil, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "Error nvram at handle 0x%x", handle)
	}

	return data, nil
}

func (tpm *trustedPlatformModule) NVWrite(nvHandle int, data []byte) error {

	// Verify that the provided handle is within the range of nv space
	if nvHandle < minNvHandle || nvHandle > maxNvHandle {
		return ErrHandleOutOfRange
	}

	if len(data) == 0 || len(data) > maxNvSize {
		return errors.Wrapf(ErrNvInvalidSize, "The length %d provided to NVWrite must be between zero and %d", len(data), maxNvSize)
	}

	handle := tpm2.Handle(nvHandle)

	// return an error if the nv index does not exist
	if !tpm.ctx.DoesHandleExist(handle) {
		return ErrorNvIndexDoesNotExist
	}

	nvContext, err := tpm.ctx.NewResourceContext(handle)
	if err != nil {
		return errors.Wrapf(err, "Failed to create resource context at handle 0x%x", handle)
	}
	nvContext.SetAuthValue(tpm.ownerAuth)

	session, err := tpm.ctx.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return err
	}

	err = tpm.ctx.NVWrite(tpm.ctx.OwnerHandleContext(), nvContext, data, 0, session)
	if err != nil {
		return errors.Wrapf(ErrNvWriteFailed, "Index 0x%x: %s", nvHandle, err.Error())
	}

	logrus.Debugf("Successfully wrote %d bytes at NV index 0x%x", len(data), nvHandle)
	return nil
}

func (tpm *trustedPlatformModule) NVDelete(nvHandle int) error {

	// Verify that the provided handle is within the range of nv space
	if nvHandle < minNvHandle || nvHandle > maxNvHandle {
		return ErrHandleOutOfRange
	}

	handle := tpm2.Handle(nvHandle)

	// return an error if the nv index does not exist
	if !tpm.ctx.DoesHandleExist(handle) {
		return ErrorNvIndexDoesNotExist
	}

	nvContext, err := tpm.ctx.NewResourceContext(handle)
	if err != nil {
		return errors.Wrapf(err, "Failed to create resource context for handle 0x%x", handle)
	}
	nvContext.SetAuthValue(tpm.ownerAuth)

	err = tpm.ctx.NVUndefineSpace(tpm.ctx.OwnerHandleContext(), nvContext, nil)
	if err != nil {
		return errors.Wrapf(ErrNvReleaseFailed, "Index 0x%x: %s", nvHandle, err.Error())
	}

	return nil
}

func (tpm *trustedPlatformModule) NVDefine(nvHandle int, len int) error {

	// Verify that the provided handle is within the range of nv space
	if nvHandle < minNvHandle || nvHandle > maxNvHandle {
		return ErrHandleOutOfRange
	}

	if len == 0 || len > maxNvSize {
		return errors.Wrapf(ErrNvInvalidSize, "The length %d provided to NVDefine is not between zero and %d", len, maxNvSize)
	}

	handle := tpm2.Handle(nvHandle)

	// return an error if the nv index already exists
	if tpm.ctx.DoesHandleExist(handle) {
		return ErrExistingHandle
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
		return errors.Wrapf(ErrNvDefineSpaceFailed, "Index 0x%x: %s", nvHandle, err.Error())
	}

	return nil
}

func (tpm *trustedPlatformModule) NVExists(nvHandle int) bool {

	if nvHandle < minNvHandle || nvHandle > maxNvHandle {
		logrus.Errorf("NV handle 0x%x is out of range", nvHandle)
		return false
	}

	handle := tpm2.Handle(nvHandle)
	if handle.Type() != tpm2.HandleTypeNVIndex {
		logrus.Errorf("Cannot determine if nv ram exists at invalid handle 0x%x", nvHandle)
		return false
	}

	return tpm.ctx.DoesHandleExist(handle)
}
