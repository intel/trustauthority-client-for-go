/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tdx

import (
	"testing"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
)

func TestCollectEvidencePositive(t *testing.T) {

	mockCfsQuoteProvider := &MockCfsQuoteProvider{}
	mockCfsQuoteProvider.On("getQuoteFromConfigFS", mock.Anything).Return([]byte("quote"), nil)

	adapter := tdxAdapter{
		eventLogsDisabled: true,
		cfsQuoteProvider:  mockCfsQuoteProvider,
	}

	_, err := adapter.CollectEvidence([]byte("nonce"))
	if err != nil {
		t.Errorf("Error: %v", err)
	}
}

func TestCollectEvidenceConfigFsError(t *testing.T) {

	mockCfsQuoteProvider := &MockCfsQuoteProvider{}
	mockCfsQuoteProvider.On("getQuoteFromConfigFS", mock.Anything).Return([]byte{}, errors.New("unit test failure"))

	adapter := tdxAdapter{
		eventLogsDisabled: true,
		cfsQuoteProvider:  mockCfsQuoteProvider,
	}

	_, err := adapter.CollectEvidence([]byte("nonce"))
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestCompositeAdapterPositive(t *testing.T) {
	mockCfsQuoteProvider := &MockCfsQuoteProvider{}
	mockCfsQuoteProvider.On("getQuoteFromConfigFS", mock.Anything).Return([]byte("quote"), nil)

	adapter := tdxAdapter{
		eventLogsDisabled: true,
		cfsQuoteProvider:  mockCfsQuoteProvider,
	}

	_, err := adapter.GetEvidence(&connector.VerifierNonce{
		Iat: make([]byte, 32),
		Val: make([]byte, 32),
	}, nil)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
}

func TestCompositeAdapterConfigFsError(t *testing.T) {
	mockCfsQuoteProvider := &MockCfsQuoteProvider{}
	mockCfsQuoteProvider.On("getQuoteFromConfigFS", mock.Anything).Return([]byte{}, errors.New("unit test failure"))

	adapter := tdxAdapter{
		eventLogsDisabled: true,
		cfsQuoteProvider:  mockCfsQuoteProvider,
	}

	_, err := adapter.GetEvidence(nil, nil)
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestCompositeAdapterCcelPositive(t *testing.T) {
	mockCfsQuoteProvider := &MockCfsQuoteProvider{}
	mockCfsQuoteProvider.On("getQuoteFromConfigFS", mock.Anything).Return([]byte("quote"), nil)

	adapter := tdxAdapter{
		eventLogsDisabled: false,
		cfsQuoteProvider:  mockCfsQuoteProvider,
		ccelTablePath:     testCcelTablePath,
		ccelDataPath:      testCcelDataPath,
	}

	evidence, err := adapter.GetEvidence(nil, nil)
	if err != nil {
		t.Errorf("Error: %v", err)
	}

	if evidence.(*compositeTdxEvidence).EventLog == nil {
		t.Errorf("expected event logs")
	}
}

func TestCompositeAdapterCcelBadTablePath(t *testing.T) {
	mockCfsQuoteProvider := &MockCfsQuoteProvider{}
	mockCfsQuoteProvider.On("getQuoteFromConfigFS", mock.Anything).Return([]byte("quote"), nil)

	adapter := tdxAdapter{
		eventLogsDisabled: false,
		cfsQuoteProvider:  mockCfsQuoteProvider,
		ccelTablePath:     testInvalidPath,
		ccelDataPath:      testCcelDataPath,
	}

	_, err := adapter.GetEvidence(nil, nil)
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestCompositeAdapterCcelBadDataPath(t *testing.T) {
	mockCfsQuoteProvider := &MockCfsQuoteProvider{}
	mockCfsQuoteProvider.On("getQuoteFromConfigFS", mock.Anything).Return([]byte("quote"), nil)

	adapter := tdxAdapter{
		eventLogsDisabled: false,
		cfsQuoteProvider:  mockCfsQuoteProvider,
		ccelTablePath:     testCcelTablePath,
		ccelDataPath:      testInvalidPath,
	}

	_, err := adapter.GetEvidence(nil, nil)
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestCompositeAdapterNew(t *testing.T) {
	adapter, err := NewCompositeEvidenceAdapter(true)
	if err != nil {
		t.Errorf("Error: %v", err)
	}

	if adapter == nil {
		t.Errorf("expected adapter")
	}

	if adapter.(*tdxAdapter).eventLogsDisabled != true {
		t.Errorf("expected eventLogsDisabled to be true")
	}

	if adapter.(*tdxAdapter).cfsQuoteProvider == nil {
		t.Errorf("expected cfsQuoteProvider")
	}

	if adapter.(*tdxAdapter).ccelTablePath != CcelPath {
		t.Errorf("expected ccelTablePath")
	}

	if adapter.(*tdxAdapter).ccelDataPath != CcelDataPath {
		t.Errorf("expected ccelDataPath")
	}

	if adapter.GetEvidenceIdentifier() != "tdx" {
		t.Errorf("expected tdx")
	}
}

type MockCfsQuoteProvider struct {
	mock.Mock
}

func (m *MockCfsQuoteProvider) getQuoteFromConfigFS(reportData []byte) ([]byte, error) {
	args := m.Called(reportData)
	return args.Get(0).([]byte), args.Error(1)
}
