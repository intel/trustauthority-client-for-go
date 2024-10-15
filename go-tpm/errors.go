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
)
