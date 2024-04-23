/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"crypto/x509"

	"github.com/pkg/errors"
)

// GetEKCertificate is a utility function that reads NV ram at the specified
// index and parses its contents into an x509 certificate
func (tpm *canonicalTpm) GetEKCertificate(nvIndex int) (*x509.Certificate, error) {

	ekDer, err := tpm.NVRead(nvIndex)
	if err != nil {
		return nil, err
	}

	if len(ekDer) <= 0 {
		return nil, errors.Errorf("nvram at handle %d only contained %d bytes", nvIndex, len(ekDer))
	}

	// This code is a workaround for errors that are encountered by x509.ParseCertificate.
	// It determines the length of the certificate by parsing the raw DER bytes.
	var length int
	lengthByte := ekDer[1]
	if lengthByte&0x80 == 0x80 {
		// Indefinite-length form
		numBytes := int(lengthByte & 0x7F)

		for i := 0; i < numBytes; i++ {
			length = length<<8 | int(ekDer[2+i])
		}
	} else {
		// Definite-length form
		length = int(lengthByte)
	}

	ekCert, err := x509.ParseCertificate(ekDer[:length+4])
	if err != nil {
		return nil, err
	}

	return ekCert, nil
}
