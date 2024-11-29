/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package cmd

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/go-tdx"
	"github.com/intel/trustauthority-client/go-tpm"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

// Contains common functions, variable and mocks used for unit testing

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetReportCaller(true)

	// Create a x509 cert for unit tests
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Amber",
		},
		Issuer: pkix.Name{
			CommonName: "Amber",
		},
		SignatureAlgorithm:    x509.SHA384WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(365, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SerialNumber:          serialNumber,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	testCertificate, err = x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	// Encrypt the AK certificate
	testAesKey = make([]byte, 32)
	testEncryptedAkCert, err = aesEncrypt(der, testAesKey)
	if err != nil {
		panic(err)
	}

	// Create an RSA public AK for unit  tests
	akPriv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	testAkPub = akPriv.Public().(*rsa.PublicKey)
}

var (
	testEkHandle        = 0x81000F00
	testAkHandle        = 0x81000F01
	testCertificate     *x509.Certificate
	testEncryptedAkCert []byte
	testAkPub           *rsa.PublicKey
	testAesKey          []byte
)

func aesEncrypt(plainText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// GCM mode, needs a nonce. Nonce size can be standard for GCM (12 bytes)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Encrypt the plaintext and prepend the nonce to the ciphertext
	ciphertext := aesGCM.Seal(nil, nonce, plainText, nil)
	ciphertext = append(nonce, ciphertext...)

	return ciphertext, nil
}

// MockConnector
type MockConnector struct {
	mock.Mock
}

func (m *MockConnector) GetTokenSigningCertificates() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockConnector) GetNonce(a connector.GetNonceArgs) (connector.GetNonceResponse, error) {
	args := m.Called(a)
	return args.Get(0).(connector.GetNonceResponse), args.Error(1)
}

func (m *MockConnector) GetToken(a connector.GetTokenArgs) (connector.GetTokenResponse, error) {
	args := m.Called(a)
	return args.Get(0).(connector.GetTokenResponse), args.Error(1)
}

func (m *MockConnector) Attest(a connector.AttestArgs) (connector.AttestResponse, error) {
	args := m.Called(a)
	return args.Get(0).(connector.AttestResponse), args.Error(1)
}

func (m *MockConnector) VerifyToken(s string) (*jwt.Token, error) {
	args := m.Called(s)
	return args.Get(0).(*jwt.Token), args.Error(1)
}

func (m *MockConnector) GetAKCertificate(ekCert *x509.Certificate, tpmtPublic []byte) ([]byte, []byte, []byte, error) {
	args := m.Called(ekCert, tpmtPublic)
	return args.Get(0).([]byte), args.Get(1).([]byte), args.Get(2).([]byte), args.Error(3)
}

func (m *MockConnector) GetTpmToken(quote, signature, pcrs, nonce []byte, akCertificate *x509.Certificate, policyIds []uuid.UUID) (*connector.GetTokenResponse, error) {
	args := m.Called(quote, signature, pcrs, nonce, akCertificate, policyIds)
	return args.Get(0).(*connector.GetTokenResponse), args.Error(1)
}

func (m *MockConnector) AttestEvidence(evidence interface{}, cloudProvider string, reqId string) (connector.AttestResponse, error) {
	args := m.Called(evidence, cloudProvider, reqId)
	return args.Get(0).(connector.AttestResponse), args.Error(1)
}

// MockTpmFactory
type MockTpmFactory struct {
	mock.Mock
}

func (m *MockTpmFactory) New(deviceType tpm.TpmDeviceType, ownerAuth string) (tpm.TrustedPlatformModule, error) {
	args := m.Called(deviceType, ownerAuth)
	return args.Get(0).(tpm.TrustedPlatformModule), args.Error(1)
}

// MockTpm
type MockTpm struct {
	mock.Mock
}

func (m *MockTpm) CreateEK(ekHandle int) error {
	args := m.Called(ekHandle)
	return args.Error(0)
}
func (m *MockTpm) CreateAK(akHandle int, ekHandle int) error {
	args := m.Called(ekHandle, ekHandle)
	return args.Error(0)
}

func (m *MockTpm) ActivateCredential(ekHandle int, akHandle int, credentialBlob []byte, secret []byte) ([]byte, error) {
	args := m.Called(ekHandle, akHandle, credentialBlob, secret)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockTpm) NVRead(nvHandle int) ([]byte, error) {
	args := m.Called(nvHandle)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockTpm) NVWrite(nvHandle int, data []byte) error {
	args := m.Called(nvHandle, data)
	return args.Error(0)
}

func (m *MockTpm) NVExists(nvHandle int) bool {
	args := m.Called(nvHandle)
	return args.Get(0).(bool)
}

func (m *MockTpm) NVDefine(nvHandle int, len int) error {
	args := m.Called(nvHandle, len)
	return args.Error(0)
}

func (m *MockTpm) NVDelete(nvHandle int) error {
	args := m.Called(nvHandle)
	return args.Error(0)
}

func (m *MockTpm) ReadPublic(handle int) (crypto.PublicKey, []byte, []byte, error) {
	args := m.Called(handle)
	return args.Get(0).(crypto.PublicKey), args.Get(1).([]byte), args.Get(2).([]byte), args.Error(3)
}

func (m *MockTpm) GetEKCertificate(nvIndex int) (*x509.Certificate, error) {
	args := m.Called(nvIndex)
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

func (m *MockTpm) GetQuote(akHandle int, nonce []byte, selection ...tpm.PcrSelection) ([]byte, []byte, error) {
	args := m.Called(akHandle, nonce, selection)
	return args.Get(0).([]byte), args.Get(1).([]byte), args.Error(2)
}

func (m *MockTpm) GetPcrs(selection ...tpm.PcrSelection) ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockTpm) HandleExists(handle int) bool {
	args := m.Called(handle)
	return args.Get(0).(bool)
}

func (m *MockTpm) Close() {
	return
}

// MockConnectorFactory
type MockConnectorFactory struct {
	mock.Mock
}

func (m *MockConnectorFactory) NewConnector(cfg *connector.Config) (connector.Connector, error) {
	args := m.Called(cfg)
	return args.Get(0).(connector.Connector), args.Error(1)
}

// MockConfigFactory
type MockConfigFactory struct {
	mock.Mock
}

func (m *MockConfigFactory) LoadConfig(path string) (*Config, error) {
	args := m.Called(path)
	return args.Get(0).(*Config), args.Error(1)
}

// MockTdxAdapterFactory
type MockTdxAdapterFactory struct {
	mock.Mock
}

func (m *MockTdxAdapterFactory) New(cloudProvider string, evLogParser tdx.EventLogParser) (connector.CompositeEvidenceAdapter, error) {
	args := m.Called(cloudProvider, evLogParser)
	return args.Get(0).(connector.CompositeEvidenceAdapter), args.Error(1)
}

// MockCompositeAdapter
type MockCompositeEvidenceAdapter struct {
	mock.Mock
}

func (m *MockCompositeEvidenceAdapter) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (interface{}, error) {
	args := m.Called(verifierNonce, userData)
	return args.Get(0), args.Error(1)
}

func (m *MockCompositeEvidenceAdapter) GetEvidenceIdentifier() string {
	args := m.Called()
	return args.String(0)
}
