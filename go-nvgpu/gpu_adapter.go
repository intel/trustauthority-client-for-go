/*
 *   Copyright (c) 2025 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package nvgpu

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/intel/trustauthority-client/go-connector"
)

// HopperArch is the architecture identifier for Hopper GPUs.
const HopperArch = "hopper"

// GPUEvidence represents the evidence collected from a GPU attestation operation.
type GPUEvidence struct {
	Nonce         string                   `json:"gpu_nonce"`                // The nonce used for attestation, hex-encoded.
	VerifierNonce *connector.VerifierNonce `json:"verifier_nonce,omitempty"` // Optional verifier nonce.
	Arch          string                   `json:"arch"`                     // The GPU architecture.
	EvidenceList  []Evidence               `json:"evidence_list"`            // List of evidence from multiple GPUs (if applicable).
	NrasApiKey    string                   `json:"nras_apikey,omitempty"`    // Optional API key for nras authentication.
}

type Evidence struct {
	Evidence        string `json:"evidence"`
	Certificate     string `json:"certificate"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
}

// GPUAdapter provides methods to collect and format GPU attestation evidence.
type GPUAdapter struct {
	gpuAttester GPUAttester
	nrasApiKey  string
}

// GPUAttester defines the interface for obtaining remote GPU attestation evidence.
type GPUAttester interface {
	GetRemoteEvidence([]byte) ([]RemoteEvidence, error)
}

// GPUAdapterOptions holds configuration options for GPUAdapter.
type GPUAdapterOptions struct {
	GpuAttester GPUAttester
	NrasApiKey  string
}

// Option is a function that configures GPUAdapterOptions.
type Option func(*GPUAdapterOptions)

// WithGpuAttester sets a custom GPUAttester in the adapter options.
func WithGpuAttester(gpuAttester GPUAttester) Option {
	return func(options *GPUAdapterOptions) {
		options.GpuAttester = gpuAttester
	}
}

// WithNrasApiKey sets the NRAS API key in the adapter options.
func WithNrasApiKey(nrasApiKey string) Option {
	return func(options *GPUAdapterOptions) {
		options.NrasApiKey = nrasApiKey
	}
}

// NewCompositeEvidenceAdapter creates a new GPUAdapter as a CompositeEvidenceAdapter.
// It accepts optional configuration options.
func NewCompositeEvidenceAdapter(opts ...Option) connector.CompositeEvidenceAdapter {
	options := &GPUAdapterOptions{
		GpuAttester: NewGpuAttester(nil),
		NrasApiKey:  "",
	}
	for _, opt := range opts {
		opt(options)
	}
	return &GPUAdapter{
		gpuAttester: options.GpuAttester,
		nrasApiKey:  options.NrasApiKey,
	}
}

// GetEvidenceIdentifier returns the identifier string for this evidence adapter.
func (*GPUAdapter) GetEvidenceIdentifier() string {
	return "nvgpu"
}

// collectEvidence collects and formats GPU attestation evidence using the provided nonce.
func (g *GPUAdapter) collectEvidence(nonce []byte) (GPUEvidence, error) {
	hash := sha256.Sum256(nonce)
	evidenceList, err := g.gpuAttester.GetRemoteEvidence(hash[:])
	if err != nil {
		return GPUEvidence{}, fmt.Errorf("failed to get remote evidence: %v", err)
	}

	if len(evidenceList) == 0 {
		return GPUEvidence{}, fmt.Errorf("no evidence returned")
	}

	// map evidence list to evidence struct list
	evidenceStructList := make([]Evidence, len(evidenceList))
	for i, e := range evidenceList {
		evidenceStructList[i] = Evidence{
			Evidence:        e.Evidence,
			Certificate:     e.Certificate,
			FirmwareVersion: e.FirmwareVersion,
		}
	}

	hexNonce := fmt.Sprintf("%x", hash)
	return GPUEvidence{
		Arch:         evidenceList[0].Arch,
		Nonce:        hexNonce,
		EvidenceList: evidenceStructList,
		NrasApiKey:   g.nrasApiKey,
	}, nil
}

// GetEvidence collects GPU attestation evidence, optionally using a verifier nonce and user data.
// Returns the evidence or an error.
func (adapter *GPUAdapter) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (any, error) {
	var nonce []byte

	if verifierNonce != nil && len(verifierNonce.Val) > 0 && len(verifierNonce.Iat) > 0 {
		// Pre-allocate slice with exact size needed
		nonce = make([]byte, len(verifierNonce.Val)+len(verifierNonce.Iat))
		copy(nonce, verifierNonce.Val)
		copy(nonce[len(verifierNonce.Val):], verifierNonce.Iat[:])
	} else {
		// Use crypto/rand directly with pre-allocated slice
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
		evidence.VerifierNonce = verifierNonce
	}

	if adapter.nrasApiKey != "" {
		evidence.NrasApiKey = adapter.nrasApiKey
	}

	return &evidence, nil
}
