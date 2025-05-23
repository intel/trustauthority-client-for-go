/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tpm

import (
	"testing"
)

func TestEkCertificatePositive(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	_, err = tpm.GetEKCertificate(DefaultEkNvIndex)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEkCertificateInvalidHandle(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	_, err = tpm.GetEKCertificate(DefaultEkNvIndex + 1)
	if err != ErrorNvIndexDoesNotExist {
		t.Fatal("expected error, got nil")
	}
}

func TestEkCertificateNotACertificate(t *testing.T) {
	tpm, err := newTestTpm()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	b := make([]byte, 256)

	err = tpm.NVDefine(DefaultEkNvIndex+1, len(b))
	if err != nil {
		t.Fatal(err)
	}

	err = tpm.NVWrite(DefaultEkNvIndex+1, b)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tpm.GetEKCertificate(DefaultEkNvIndex + 1)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
