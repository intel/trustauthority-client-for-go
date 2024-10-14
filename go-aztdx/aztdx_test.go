/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package aztdx

import (
	"crypto"
	"crypto/x509"

	"github.com/intel/trustauthority-client/go-tpm"
	"github.com/stretchr/testify/mock"
)

// -----------------------------------------------------------------------------
// MockTpmFactory
// -----------------------------------------------------------------------------
type MockTpmFactory struct {
	mock.Mock
}

func (m *MockTpmFactory) New(deviceType tpm.TpmDeviceType, ownerAuth string) (tpm.TrustedPlatformModule, error) {
	args := m.Called(deviceType, ownerAuth)
	return args.Get(0).(tpm.TrustedPlatformModule), args.Error(1)
}

// -----------------------------------------------------------------------------
// MockTpm
// -----------------------------------------------------------------------------
type MockTpm struct {
	mock.Mock
}

func (m *MockTpm) CreateEK(ekHandle int) error {
	args := m.Called(ekHandle)
	return args.Error(0)
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
	args := m.Called(selection)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockTpm) HandleExists(handle int) bool {
	args := m.Called(handle)
	return args.Get(0).(bool)
}

func (m *MockTpm) Close() {
	m.Called()
}
