package nvgpu

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust"
	"github.com/intel/trustauthority-client/go-connector"
)

type GPUEvidence struct {
	Evidence      string                  `json:"evidence"`
	Certificate   string                  `json:"certificate"`
	Nonce         string                  `json:"gpu_nonce"`
	VerifierNonce connector.VerifierNonce `json:"verifier_nonce"`
}

type GPUAdapter struct {
	gpuAttester GPUAttester
}

type GPUAttester interface {
	GetRemoteEvidence([]byte) ([]gonvtrust.RemoteEvidence, error)
}

type GPUAdapterOptions struct {
	GpuAttester GPUAttester
}

type Option func(*GPUAdapterOptions)

func WithGpuAttester(gpuAttester GPUAttester) Option {
	return func(options *GPUAdapterOptions) {
		options.GpuAttester = gpuAttester
	}
}

func NewCompositeEvidenceAdapter(opts ...Option) connector.CompositeEvidenceAdapter {
	options := &GPUAdapterOptions{
		GpuAttester: gonvtrust.NewGpuAttester(false),
	}
	for _, opt := range opts {
		opt(options)
	}
	return &GPUAdapter{
		gpuAttester: options.GpuAttester,
	}
}

func (*GPUAdapter) GetEvidenceIdentifier() string {
	return "nvgpu"
}

func (g *GPUAdapter) collectEvidence(nonce []byte) (GPUEvidence, error) {
	hash := sha256.Sum256(nonce)
	// pass in false to signify we are not in test mode
	evidenceList, err := g.gpuAttester.GetRemoteEvidence(hash[:])
	if err != nil {
		return GPUEvidence{}, fmt.Errorf("failed to get remote evidence: %v", err)
	}

	if len(evidenceList) == 0 {
		return GPUEvidence{}, fmt.Errorf("no evidence returned")
	}
	// only single gpu attestation is supported for now
	rawEvidence := evidenceList[0]

	evidenceBytes, err := base64.StdEncoding.DecodeString(rawEvidence.Evidence)
	if err != nil {
		return GPUEvidence{}, fmt.Errorf("failed to decode evidence: %v", err)
	}
	hexEvidence := hex.EncodeToString(evidenceBytes)
	rawEvidence.Evidence = base64.StdEncoding.EncodeToString([]byte(hexEvidence))

	hexNonce := fmt.Sprintf("%x", hash)
	return GPUEvidence{
		Nonce:       hexNonce,
		Evidence:    rawEvidence.Evidence,
		Certificate: rawEvidence.Certificate,
	}, nil
}

func (adapter *GPUAdapter) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (any, error) {
	var nonce []byte
	if verifierNonce != nil {
		nonce = append(verifierNonce.Val, verifierNonce.Iat[:]...)
	}

	evidence, err := adapter.collectEvidence(nonce)
	if err != nil {
		return nil, err
	}

	evidence.VerifierNonce = *verifierNonce

	return &evidence, nil
}
