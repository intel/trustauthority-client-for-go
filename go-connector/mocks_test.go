/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/mock"
)

// ------------------------------------------------------------------------------------------------
// MockConnector
// ------------------------------------------------------------------------------------------------
type MockConnector struct {
	mock.Mock
}

func (m *MockConnector) GetTokenSigningCertificates() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockConnector) GetNonce(nonceArgs GetNonceArgs) (GetNonceResponse, error) {
	args := m.Called(nonceArgs)
	return args.Get(0).(GetNonceResponse), args.Error(1)
}

func (m *MockConnector) GetToken(tokenArgs GetTokenArgs) (GetTokenResponse, error) {
	args := m.Called(tokenArgs)
	return args.Get(0).(GetTokenResponse), args.Error(1)
}

func (m *MockConnector) Attest(attestArgs AttestArgs) (AttestResponse, error) {
	args := m.Called(attestArgs)
	return args.Get(0).(AttestResponse), args.Error(1)
}

func (m *MockConnector) VerifyToken(token string) (*jwt.Token, error) {
	args := m.Called(token)
	return args.Get(0).(*jwt.Token), args.Error(1)
}

func (m *MockConnector) AttestEvidence(evidence interface{}, cloudProvider string, reqId string) (AttestResponse, error) {
	args := m.Called(evidence, cloudProvider, reqId)
	return args.Get(0).(AttestResponse), args.Error(1)
}