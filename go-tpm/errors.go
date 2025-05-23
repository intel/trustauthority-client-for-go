/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"github.com/pkg/errors"
)

var (
	ErrHandleOutOfRange      = errors.New("handle out of range")
	ErrInvalidHandle         = errors.New("invalid handle")
	ErrExistingHandle        = errors.New("the handle already exists")
	ErrHandleDoesNotExist    = errors.New("the handle does not exist")
	ErrHandleError           = errors.New("failed to access handle")
	ErrorNvIndexDoesNotExist = errors.New("nv index does not exist")
	ErrNvReleaseFailed       = errors.New("failed to release/delete nv index")
	ErrNvDefineSpaceFailed   = errors.New("failed to define/create nv index")
	ErrNvWriteFailed         = errors.New("failed to write data to nv ram")
	ErrNvInvalidSize         = errors.New("invalid data size for nv ram")
	ErrSymlinksNotAllowed    = errors.New("symlinks are not allowed")
	ErrPathTraversal         = errors.New("path traversal detected")
	ErrQuoteFailure          = errors.New("failed to get quote")
	ErrTpmOpenFailure        = errors.New("failed to create tpm device")
	ErrPCRsFailure           = errors.New("failed to read pcrs")
	ErrFailedToReadIMALogs   = errors.New("failed to read ima log")
	ErrFailedToReadUEFILogs  = errors.New("failed to read uefi log")
	ErrReadAkFileFailure     = errors.New("failed to read ak certificate from file")
	ErrReadAkNvramInvalidHex = errors.New("invalid ak hex value")
	ErrReadAkNvramFailure    = errors.New("failed to read ak certificate from nvram")
	ErrIssuerCAHttpError     = errors.New("failed download issuer CA certificate")
	ErrIssuerCAStatusError   = errors.New("failed download issuer CA certificate")
	ErrInvalidCertificate    = errors.New("invalid certificate")
	ErrInvalidPemType        = errors.New("invalid pem type, expected CERTIFICATE")
)
