/*
 *   Copyright (c) 2025 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package nvgpu

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sync"
)

// CertChain represents a chain of X.509 certificates, typically used for certificate validation
// and encoding operations. It holds the certificates in DER-encoded byte slices.
type CertChain struct {
	certs [][]byte
}

// NewCertChainFromPemData creates a new CertChain from the provided PEM-encoded certificate chain data.
// It parses the input data and extracts each certificate, storing them as DER-encoded byte slices.
func NewCertChainFromPemData(chainData []byte) *CertChain {
	var certs [][]byte
	remainingData := chainData
	for {
		block, rest := pem.Decode(remainingData)
		if block == nil {
			break
		}
		certs = append(certs, block.Bytes)
		remainingData = rest
	}

	return &CertChain{certs: certs}
}

// verify checks the validity of the certificate chain.
// It performs the following steps:
// 1. Parses all DER-encoded certificates into x509.Certificate objects
// 2. Verifies the chain contains at least two certificates (minimum viable chain)
// 3. Sets up verification pools for roots and intermediates
// 4. Verifies the leaf certificate against the chain
//
// Certificate chain layout assumptions:
// - certs[0]: Leaf certificate (the certificate being verified)
// - certs[1...n-2]: Intermediate certificates (if any)
// - certs[n-1]: Root certificate (trust anchor)
//
// The function expects the certificates to be in order from leaf to root,
// forming a chain where each certificate is signed by the next one in the chain.
func (c *CertChain) verify() error {
	var parsedCerts []*x509.Certificate

	for _, certData := range c.certs {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}
		parsedCerts = append(parsedCerts, cert)
	}

	// A valid certificate chain must have at least 2 certificates:
	// 1. A leaf certificate (the entity being verified)
	// 2. A root certificate (the trust anchor)
	// Without at least these two, certificate path validation cannot be performed
	if len(parsedCerts) < 2 {
		return fmt.Errorf("certificate chain must contain at least two certificates")
	}

	// Set up certificate pools for verification
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	// The last certificate is treated as the root CA (trust anchor)
	// All other certificates except the leaf are treated as intermediates
	for i, cert := range parsedCerts {
		if i == len(parsedCerts)-1 {
			// Add the last certificate as a trusted root
			roots.AddCert(cert)
		} else {
			// Add all other certificates (including the leaf) as intermediates
			// Note: The leaf is added to intermediates but will be verified separately
			intermediates.AddCert(cert)
		}
	}

	// Verification options for the leaf certificate
	opts := x509.VerifyOptions{
		Roots:         roots,         // Trust anchor (root certificate)
		Intermediates: intermediates, // Intermediate certificates
	}

	// Verify the leaf certificate (first in the chain) against the
	// established trust chain
	_, err := parsedCerts[0].Verify(opts)
	return err
}

// Use a pool for byte buffers to reduce allocations during encoding
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// Optimize encodeBase64 to reduce allocations
func (c *CertChain) encodeBase64() (string, error) {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	// Pre-allocate with expected size
	buf.Grow(len(c.certs) * 64) // Rough estimate for PEM certificates

	for _, cert := range c.certs {
		// Write PEM block directly to buffer
		if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return "", fmt.Errorf("failed to encode certificate: %v", err)
		}
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
