/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"github.com/sirupsen/logrus"
	"testing"
)

// TODO [CASSINI-17044]: Current unit tests are for debugging phyical TPMs and will be
// be updated at a later date.
func TestEkCertificate(t *testing.T) {
	tpm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	cert, err := tpm.GetEKCertificate(DefaultEkNvIndex)
	if err != nil {
		t.Fatal(err)
	}

	logrus.Debugf("%+v", cert)
}
