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
	ErrHandleOutOfRange      = errors.New("Handle out of range")
	ErrInvalidHandle         = errors.New("Invalid handle")
	ErrExistingHandle        = errors.New("The handle already exists")
	ErrHandleDoesNotExist    = errors.New("The handle does not exist")
	ErrHandleError           = errors.New("Failed to access handle")
	ErrorNvIndexDoesNotExist = errors.New("NV index does not exist")
	ErrNvReleaseFailed       = errors.New("Failed to release/delete NV index")
	ErrNvDefineSpaceFailed   = errors.New("Failed to define/create NV index")
	ErrNvSizeExceeded        = errors.New("The size of the data requested to store in NV is too large")
	ErrNvWriteFailed         = errors.New("Failed to write data to NV ram")
)
