package nvgpu

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust"
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockGPUAttester is a mock implementation of the GPUAttester interface
type MockGPUAttester struct {
	mock.Mock
}

func (m *MockGPUAttester) GetRemoteEvidence(nonce []byte) ([]gonvtrust.RemoteEvidence, error) {
	args := m.Called(nonce)
	return args.Get(0).([]gonvtrust.RemoteEvidence), args.Error(1)
}

func TestNewCompositeEvidenceAdapter(t *testing.T) {
	mockAttester := new(MockGPUAttester)
	adapter := NewCompositeEvidenceAdapter(WithGpuAttester(mockAttester))

	assert.NotNil(t, adapter)
	assert.IsType(t, &GPUAdapter{}, adapter)
}

func TestGetEvidenceIdentifier(t *testing.T) {
	mockAttester := new(MockGPUAttester)
	adapter := NewCompositeEvidenceAdapter(WithGpuAttester(mockAttester))

	assert.Equal(t, "nvgpu", adapter.GetEvidenceIdentifier())
}

func TestGetEvidence(t *testing.T) {
	mockAttester := new(MockGPUAttester)
	adapter := NewCompositeEvidenceAdapter(WithGpuAttester(mockAttester))

	verifierNonce := &connector.VerifierNonce{
		Val: []byte("verifier_nonce"),
		Iat: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	nonce := append(verifierNonce.Val, verifierNonce.Iat[:]...)
	hash := sha256.Sum256(nonce)
	expectedEvidence := gonvtrust.RemoteEvidence{
		Evidence:    base64.StdEncoding.EncodeToString([]byte("test_evidence")),
		Certificate: "test_certificate",
	}
	mockAttester.On("GetRemoteEvidence", hash[:]).Return([]gonvtrust.RemoteEvidence{expectedEvidence}, nil)

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

func TestGetEvidence_AttesterReturnsError(t *testing.T) {
	mockAttester := new(MockGPUAttester)
	adapter := NewCompositeEvidenceAdapter(WithGpuAttester(mockAttester))

	verifierNonce := &connector.VerifierNonce{
		Val: []byte("verifier_nonce"),
		Iat: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	nonce := append(verifierNonce.Val, verifierNonce.Iat[:]...)
	hash := sha256.Sum256(nonce)
	mockAttester.On("GetRemoteEvidence", hash[:]).Return([]gonvtrust.RemoteEvidence{}, fmt.Errorf("test_error"))

	evidence, err := adapter.GetEvidence(verifierNonce, nil)
	assert.Error(t, err)
	assert.Empty(t, evidence)
}

func TestGetEvidence_AttesterReturnsNoEvidence(t *testing.T) {
	mockAttester := new(MockGPUAttester)
	adapter := NewCompositeEvidenceAdapter(WithGpuAttester(mockAttester))

	verifierNonce := &connector.VerifierNonce{
		Val: []byte("verifier_nonce"),
		Iat: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	nonce := append(verifierNonce.Val, verifierNonce.Iat[:]...)
	hash := sha256.Sum256(nonce)
	mockAttester.On("GetRemoteEvidence", hash[:]).Return([]gonvtrust.RemoteEvidence{}, nil)

	evidence, err := adapter.GetEvidence(verifierNonce, nil)
	assert.Error(t, err)
	assert.Empty(t, evidence)
}

func TestGetEvidence_AttesterReturnsInvalidBase64(t *testing.T) {
	mockAttester := new(MockGPUAttester)
	adapter := NewCompositeEvidenceAdapter(WithGpuAttester(mockAttester))

	verifierNonce := &connector.VerifierNonce{
		Val: []byte("verifier_nonce"),
		Iat: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	nonce := append(verifierNonce.Val, verifierNonce.Iat[:]...)
	hash := sha256.Sum256(nonce)
	expectedEvidence := gonvtrust.RemoteEvidence{
		Evidence:    "invalid_base64",
		Certificate: "test_certificate",
	}
	mockAttester.On("GetRemoteEvidence", hash[:]).Return([]gonvtrust.RemoteEvidence{expectedEvidence}, nil)

	evidence, err := adapter.GetEvidence(verifierNonce, nil)
	assert.Error(t, err)
	assert.Empty(t, evidence)
}

func TestGetEvidence_VerifierNonceIsMissing(t *testing.T) {
	mockAttester := new(MockGPUAttester)
	adapter := NewCompositeEvidenceAdapter(WithGpuAttester(mockAttester))

	expectedEvidence := gonvtrust.RemoteEvidence{
		Evidence:    base64.StdEncoding.EncodeToString([]byte("test_evidence")),
		Certificate: "test_certificate",
	}
	mockAttester.On("GetRemoteEvidence", mock.AnythingOfType("[]uint8")).Return([]gonvtrust.RemoteEvidence{expectedEvidence}, nil)

	evidence, err := adapter.GetEvidence(nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, evidence)

	gpuEvidence, ok := evidence.(*GPUEvidence)
	assert.True(t, ok)
	assert.Equal(t, expectedEvidence.Certificate, gpuEvidence.Certificate)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte("test_evidence")))), gpuEvidence.Evidence)
}
