package nvgpu

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust"
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/sirupsen/logrus"
)

const HopperArch = "hopper"

type GPUEvidence struct {
	Evidence      string                  `json:"evidence"`
	Certificate   string                  `json:"certificate"`
	Nonce         string                  `json:"gpu_nonce"`
	VerifierNonce connector.VerifierNonce `json:"verifier_nonce"`
	Arch          string                  `json:"arch"`
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
		GpuAttester: gonvtrust.NewGpuAttester(nil),
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

	if len(evidenceList) > 1 {
		logrus.Warn("more than one evidence returned, only using the first one")
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
		Arch:        HopperArch,
		Nonce:       hexNonce,
		Evidence:    rawEvidence.Evidence,
		Certificate: rawEvidence.Certificate,
	}, nil
}

func (adapter *GPUAdapter) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (any, error) {
	var nonce []byte
	if verifierNonce != nil && len(verifierNonce.Val) > 0 && len(verifierNonce.Iat) > 0 {
		nonce = append(verifierNonce.Val, verifierNonce.Iat[:]...)
	} else {
		nonce = make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate random nonce: %v", err)
		}
	}

	evidence, err := adapter.collectEvidence(nonce)
	if err != nil {
		return nil, err
	}

	if verifierNonce != nil {
		evidence.VerifierNonce = *verifierNonce
	}
	return &evidence, nil
}
