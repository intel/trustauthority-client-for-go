/*
 *   Copyright (c) 2025 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package nvgpu

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/sirupsen/logrus"
)

// HopperArch is the architecture identifier for Hopper GPUs.
const HopperArch = "hopper"

// GPUEvidence represents the evidence collected from a GPU attestation operation.
type GPUEvidence struct {
	Evidence      string                   `json:"evidence"`                 // The attestation evidence, base64-encoded.
	Certificate   string                   `json:"certificate"`              // The certificate associated with the evidence.
	Nonce         string                   `json:"gpu_nonce"`                // The nonce used for attestation, hex-encoded.
	VerifierNonce *connector.VerifierNonce `json:"verifier_nonce,omitempty"` // Optional verifier nonce.
	Arch          string                   `json:"arch"`                     // The GPU architecture.
}

// GPUAdapter provides methods to collect and format GPU attestation evidence.
type GPUAdapter struct {
	gpuAttester GPUAttester
}

// GPUAttester defines the interface for obtaining remote GPU attestation evidence.
type GPUAttester interface {
	GetRemoteEvidence([]byte) ([]RemoteEvidence, error)
}

// GPUAdapterOptions holds configuration options for GPUAdapter.
type GPUAdapterOptions struct {
	GpuAttester GPUAttester
}

// Option is a function that configures GPUAdapterOptions.
type Option func(*GPUAdapterOptions)

// WithGpuAttester sets a custom GPUAttester in the adapter options.
func WithGpuAttester(gpuAttester GPUAttester) Option {
	return func(options *GPUAdapterOptions) {
		options.GpuAttester = gpuAttester
	}
}

// NewCompositeEvidenceAdapter creates a new GPUAdapter as a CompositeEvidenceAdapter.
// It accepts optional configuration options.
func NewCompositeEvidenceAdapter(opts ...Option) connector.CompositeEvidenceAdapter {
	options := &GPUAdapterOptions{
		GpuAttester: NewGpuAttester(nil),
	}
	for _, opt := range opts {
		opt(options)
	}
	return &GPUAdapter{
		gpuAttester: options.GpuAttester,
	}
}

// GetEvidenceIdentifier returns the identifier string for this evidence adapter.
func (*GPUAdapter) GetEvidenceIdentifier() string {
	return "nvgpu"
}

// collectEvidence collects and formats GPU attestation evidence using the provided nonce.
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

	// Optimize evidence collection
	evidence, err := adapter.collectEvidence(nonce)
	if err != nil {
		return nil, err
	}

	if verifierNonce != nil {
		evidence.VerifierNonce = verifierNonce
	}

	return &evidence, nil
}
