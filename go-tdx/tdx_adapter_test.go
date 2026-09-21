/*
 *   Copyright (c) 2022-2025 Intel Corporation
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
		withCcel:         false,
		cfsQuoteProvider: mockCfsQuoteProvider,
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
		withCcel:         false,
		cfsQuoteProvider: mockCfsQuoteProvider,
	}

	_, err := adapter.CollectEvidence([]byte("nonce"))
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestCollectEvidenceEmptyQuote(t *testing.T) {

	mockCfsQuoteProvider := &MockCfsQuoteProvider{}
	mockCfsQuoteProvider.On("getQuoteFromConfigFS", mock.Anything).Return([]byte{}, nil)

	adapter := tdxAdapter{
		withCcel:         false,
		cfsQuoteProvider: mockCfsQuoteProvider,
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
		withCcel:         false,
		cfsQuoteProvider: mockCfsQuoteProvider,
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
		withCcel:         false,
		cfsQuoteProvider: mockCfsQuoteProvider,
	}

	_, err := adapter.GetEvidence(nil, nil)
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestCompositeAdapterCcelPositive(t *testing.T) {

	// use test data files
	ccelTablePath = testCcelTablePath
	ccelDataPath = testCcelDataPath

	mockCfsQuoteProvider := &MockCfsQuoteProvider{}
	mockCfsQuoteProvider.On("getQuoteFromConfigFS", mock.Anything).Return([]byte("quote"), nil)

	adapter := tdxAdapter{
		withCcel:         true,
		cfsQuoteProvider: mockCfsQuoteProvider,
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

	// use invalid test data files
	ccelTablePath = testInvalidPath
	ccelDataPath = testCcelDataPath

	mockCfsQuoteProvider := &MockCfsQuoteProvider{}
	mockCfsQuoteProvider.On("getQuoteFromConfigFS", mock.Anything).Return([]byte("quote"), nil)

	adapter := tdxAdapter{
		withCcel:         true,
		cfsQuoteProvider: mockCfsQuoteProvider,
	}

	_, err := adapter.GetEvidence(nil, nil)
	if !errors.Is(err, ErrorCcelTableNotFound) {
		t.Errorf("expected ErrorCcelTableNotFound")
	}
}

func TestCompositeAdapterNew(t *testing.T) {
	t.Setenv(QuoteBrokerSocketEnv, "")
	adapter, err := NewCompositeEvidenceAdapter(false)
	if err != nil {
		t.Errorf("Error: %v", err)
	}

	if adapter == nil {
		t.Errorf("expected adapter")
	}

	if adapter.(*tdxAdapter).withCcel != false {
		t.Errorf("expected withCcel to be false")
	}

	if adapter.(*tdxAdapter).cfsQuoteProvider == nil {
		t.Errorf("expected cfsQuoteProvider")
	}

	if adapter.GetEvidenceIdentifier() != "tdx" {
		t.Errorf("expected tdx")
	}
}

func TestCompositeAdapterNewWithBroker(t *testing.T) {
	t.Setenv(QuoteBrokerSocketEnv, "/run/tdx-quote-broker/quote.sock")
	adapter, err := NewCompositeEvidenceAdapter(false)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	if _, ok := adapter.(*tdxAdapter).cfsQuoteProvider.(*brokerQuoteProvider); !ok {
		t.Errorf("got provider %T, want *brokerQuoteProvider", adapter.(*tdxAdapter).cfsQuoteProvider)
	}
}

func TestCompositeAdapterNewRejectsRelativeBrokerPath(t *testing.T) {
	t.Setenv(QuoteBrokerSocketEnv, "quote.sock")
	adapter, err := NewCompositeEvidenceAdapter(false)
	if err == nil {
		t.Fatal("expected relative broker socket path to fail")
	}
	if adapter != nil {
		t.Error("expected nil adapter")
	}
}

type MockCfsQuoteProvider struct {
	mock.Mock
}

func (m *MockCfsQuoteProvider) getQuoteFromConfigFS(reportData []byte) ([]byte, error) {
	args := m.Called(reportData)
	return args.Get(0).([]byte), args.Error(1)
}
