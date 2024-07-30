/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package sevsnp

import (
	"crypto/rsa"
	"math/big"
)

// ZeroizeByteArray overwrites a byte array's data with zeros
func ZeroizeByteArray(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

// ZeroizeBigInt replaces the big integer's byte array with
// zeroes.  This function will panic if the bigInt parameter is nil.
func ZeroizeBigInt(bigInt *big.Int) {
	if bigInt == nil {
		panic("The bigInt parameter cannot be nil")
	}

	bytes := make([]byte, len(bigInt.Bytes()))
	bigInt.SetBytes(bytes)
}

// ZeroizeRSAPrivateKey clears the private key's "D" and
// "Primes" (big int) values.  This function will panic if the privateKey
// parameter is nil.
func ZeroizeRSAPrivateKey(privateKey *rsa.PrivateKey) {
	if privateKey == nil {
		panic("The private key parameter cannot be nil")
	}

	ZeroizeBigInt(privateKey.D)
	for _, bigInt := range privateKey.Primes {
		ZeroizeBigInt(bigInt)
	}
}
