/*
 *   Copyright (c) 2025 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package nvgpu

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockGPUAttester is a mock implementation of the GPUAttester interface
type MockGPUAttester struct {
	mock.Mock
}

// GetRemoteEvidence mocks the GPUAttester's GetRemoteEvidence method.
// It returns a slice of RemoteEvidence and an error based on the mock's expectations.
func (m *MockGPUAttester) GetRemoteEvidence(nonce []byte) ([]RemoteEvidence, error) {
	args := m.Called(nonce)
	return args.Get(0).([]RemoteEvidence), args.Error(1)
}

// TestNewCompositeEvidenceAdapter tests the creation of a new GPUAdapter using the composite adapter pattern.
func TestNewCompositeEvidenceAdapter(t *testing.T) {
	mockAttester := new(MockGPUAttester)
	adapter := NewCompositeEvidenceAdapter(WithGpuAttester(mockAttester))

	assert.NotNil(t, adapter)
	assert.IsType(t, &GPUAdapter{}, adapter)
}

// TestGetEvidenceIdentifier tests that the GPUAdapter returns the correct evidence identifier.
func TestGetEvidenceIdentifier(t *testing.T) {
	mockAttester := new(MockGPUAttester)
	adapter := NewCompositeEvidenceAdapter(WithGpuAttester(mockAttester))

	assert.Equal(t, "nvgpu", adapter.GetEvidenceIdentifier())
}

// TestGetEvidence tests the GetEvidence method of GPUAdapter for successful evidence retrieval and correct field values.
func TestGetEvidence(t *testing.T) {
	mockAttester := new(MockGPUAttester)
	adapter := NewCompositeEvidenceAdapter(WithGpuAttester(mockAttester))

	verifierNonce := &connector.VerifierNonce{
		Val: []byte("verifier_nonce"),
		Iat: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	nonce := append(verifierNonce.Val, verifierNonce.Iat[:]...)
	hash := sha256.Sum256(nonce)
	expectedEvidence := RemoteEvidence{
		Evidence:    base64.StdEncoding.EncodeToString([]byte("test_evidence")),
		Certificate: "test_certificate",
	}
	mockAttester.On("GetRemoteEvidence", hash[:]).Return([]RemoteEvidence{expectedEvidence}, nil)

	evidence, err := adapter.GetEvidence(verifierNonce, nil)
	assert.NoError(t, err)
	assert.NotNil(t, evidence)

	gpuEvidence, ok := evidence.(*GPUEvidence)
	assert.True(t, ok)
	assert.Equal(t, expectedEvidence.Certificate, gpuEvidence.Certificate)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte("test_evidence")))), gpuEvidence.Evidence)
	assert.Equal(t, fmt.Sprintf("%x", hash), gpuEvidence.Nonce)
	assert.Equal(t, *verifierNonce, gpuEvidence.VerifierNonce)
}

// TestGetEvidence_AttesterReturnsError tests the GetEvidence method when the attester returns an error.
func TestGetEvidence_AttesterReturnsError(t *testing.T) {
	mockAttester := new(MockGPUAttester)
	adapter := NewCompositeEvidenceAdapter(WithGpuAttester(mockAttester))

	verifierNonce := &connector.VerifierNonce{
		Val: []byte("verifier_nonce"),
		Iat: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	nonce := append(verifierNonce.Val, verifierNonce.Iat[:]...)
	hash := sha256.Sum256(nonce)
	mockAttester.On("GetRemoteEvidence", hash[:]).Return([]RemoteEvidence{}, fmt.Errorf("test_error"))

	evidence, err := adapter.GetEvidence(verifierNonce, nil)
	assert.Error(t, err)
	assert.Empty(t, evidence)
}

// TestGetEvidence_AttesterReturnsNoEvidence tests the GetEvidence method when the attester returns no evidence.
func TestGetEvidence_AttesterReturnsNoEvidence(t *testing.T) {
	mockAttester := new(MockGPUAttester)
	adapter := NewCompositeEvidenceAdapter(WithGpuAttester(mockAttester))

	verifierNonce := &connector.VerifierNonce{
		Val: []byte("verifier_nonce"),
		Iat: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	nonce := append(verifierNonce.Val, verifierNonce.Iat[:]...)
	hash := sha256.Sum256(nonce)
	mockAttester.On("GetRemoteEvidence", hash[:]).Return([]RemoteEvidence{}, nil)

	evidence, err := adapter.GetEvidence(verifierNonce, nil)
	assert.Error(t, err)
	assert.Empty(t, evidence)
}

// TestGetEvidence_AttesterReturnsInvalidBase64 tests the GetEvidence method when the attester returns invalid base64 evidence.
func TestGetEvidence_AttesterReturnsInvalidBase64(t *testing.T) {
	mockAttester := new(MockGPUAttester)
	adapter := NewCompositeEvidenceAdapter(WithGpuAttester(mockAttester))

	verifierNonce := &connector.VerifierNonce{
		Val: []byte("verifier_nonce"),
		Iat: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	nonce := append(verifierNonce.Val, verifierNonce.Iat[:]...)
	hash := sha256.Sum256(nonce)
	expectedEvidence := RemoteEvidence{
		Evidence:    "invalid_base64",
		Certificate: "test_certificate",
	}
	mockAttester.On("GetRemoteEvidence", hash[:]).Return([]RemoteEvidence{expectedEvidence}, nil)

	evidence, err := adapter.GetEvidence(verifierNonce, nil)
	assert.Error(t, err)
	assert.Empty(t, evidence)
}

// TestGetEvidence_VerifierNonceIsMissing tests the GetEvidence method when the verifier nonce is missing.
func TestGetEvidence_VerifierNonceIsMissing(t *testing.T) {
	mockAttester := new(MockGPUAttester)
	adapter := NewCompositeEvidenceAdapter(WithGpuAttester(mockAttester))

	expectedEvidence := RemoteEvidence{
		Evidence:    base64.StdEncoding.EncodeToString([]byte("test_evidence")),
		Certificate: "test_certificate",
	}
	mockAttester.On("GetRemoteEvidence", mock.AnythingOfType("[]uint8")).Return([]RemoteEvidence{expectedEvidence}, nil)

	evidence, err := adapter.GetEvidence(nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, evidence)

	gpuEvidence, ok := evidence.(*GPUEvidence)
	assert.True(t, ok)
	assert.Equal(t, expectedEvidence.Certificate, gpuEvidence.Certificate)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte("test_evidence")))), gpuEvidence.Evidence)
}
