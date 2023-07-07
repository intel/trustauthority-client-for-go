/*
 *   Copyright (c) 2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"log"
	"os"
	"testing"
)

const (
	privateKeyPath = "privatekey.pem"
	encryptedData  = "cipher"
)

func TestGenerateKeyPair(t *testing.T) {

	km := &KeyMetadata{
		KeyLength: 3072,
	}

	_, _, err := GenerateKeyPair(km)
	if err != nil {
		t.Errorf("GenerateKeyPair returned unexpected error: %v", err)
	}
}

func TestDecrypt_nonexistentKey(t *testing.T) {

	em := &EncryptionMetadata{
		PrivateKeyLocation: privateKeyPath,
	}

	_, err := Decrypt([]byte(encryptedData), em)
	if err == nil {
		t.Error("Decrypt returned nil, expected error")
	}
}

func TestDecrypt_invalidPEM(t *testing.T) {

	_ = os.WriteFile(privateKeyPath, []byte("key"), 0600)
	defer os.Remove(privateKeyPath)

	em := &EncryptionMetadata{
		PrivateKeyLocation: privateKeyPath,
	}

	_, err := Decrypt([]byte(encryptedData), em)
	if err == nil {
		t.Error("Decrypt returned nil, expected error")
	}
}

func TestDecrypt_invalidPrivateKey(t *testing.T) {

	em := &EncryptionMetadata{
		PrivateKey: []byte("key"),
	}

	_, err := Decrypt([]byte(encryptedData), em)
	if err == nil {
		t.Error("Decrypt returned nil, expected error")
	}
}

func TestDecrypt_wrongHashAlg(t *testing.T) {

	keyPair, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatal("failed to generate key pair")
	}

	em := &EncryptionMetadata{
		PrivateKey:    x509.MarshalPKCS1PrivateKey(keyPair),
		HashAlgorithm: SM3_256,
	}

	_, err = Decrypt([]byte(encryptedData), em)
	if err == nil {
		t.Error("Decrypt returned nil, expected error")
	}
}

func TestDecrypt_wrongPrivateKey(t *testing.T) {

	keyPair, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatal("failed to generate key pair")
	}

	em := &EncryptionMetadata{
		PrivateKey:    x509.MarshalPKCS1PrivateKey(keyPair),
		HashAlgorithm: SHA384,
	}

	_, err = Decrypt([]byte(encryptedData), em)
	if err == nil {
		t.Error("Decrypt returned nil, expected error")
	}
}

func TestDecrypt(t *testing.T) {

	keyPair, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatal("failed to generate key pair")
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &keyPair.PublicKey, []byte("secret"), nil)
	if err != nil {
		log.Fatal("failed to encrypt" + err.Error())
	}

	em := &EncryptionMetadata{
		PrivateKey:    x509.MarshalPKCS1PrivateKey(keyPair),
		HashAlgorithm: SHA256,
	}

	_, err = Decrypt(ciphertext, em)
	if err != nil {
		t.Errorf("Decrypt returned unexpected error: %v", err)
	}
}
