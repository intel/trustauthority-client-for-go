/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import "github.com/pkg/errors"

var (
	ErrInvalidFilePath = errors.New("Invalid invalid file path provided")
	ErrMalformedJson   = errors.New("Malformed JSON provided")
)
