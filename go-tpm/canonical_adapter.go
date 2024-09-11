/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"crypto/sha256"

	"github.com/intel/trustauthority-client/go-connector"

	"github.com/pkg/errors"
)

// TpmAdapterOptions for creating an evidence adapter using the host's TPM.
type TpmAdapterOptions func(*tpmCompositeAdapter) error

type tpmCompositeAdapter struct {
	akHandle      int
	pcrSelections []PcrSelection
	deviceType    TpmDeviceType
	ownerAuth     string
}

var defaultAdapter = tpmCompositeAdapter{
	akHandle:      DefaultAkHandle,
	pcrSelections: defaultPcrSelections,
	deviceType:    Linux,
	ownerAuth:     "",
}

// NewEvidenceAdapter creates a new composite adapter for the host's TPM.
func NewEvidenceAdapter(akHandle int, pcrSelections string, ownerAuth string) (connector.EvidenceAdapter2, error) {
	selections, err := parsePcrSelections(pcrSelections)
	if err != nil {
		return nil, err
	}

	if akHandle == 0 {
		akHandle = DefaultAkHandle
	}

	return &tpmCompositeAdapter{
		akHandle:      akHandle,
		pcrSelections: selections,
		ownerAuth:     ownerAuth,
	}, nil
}

// NewEvidenceAdapterWithOptions creates a new composite adapter for the host's TPM.
func NewEvidenceAdapterWithOptions(opts ...TpmAdapterOptions) (connector.EvidenceAdapter2, error) {
	// By default, create an adpater with default values
	tca := &defaultAdapter

	// Iterate over the options and apply them to the adapter
	for _, option := range opts {
		if err := option(tca); err != nil {
			return nil, err
		}
	}

	return tca, nil
}

// WithOwnerAuth specifies the owner password used to communicate
// with the TPM.  By default, the empty string is used.
func WithOwnerAuth(ownerAuth string) TpmAdapterOptions {
	return func(tca *tpmCompositeAdapter) error {
		tca.ownerAuth = ownerAuth
		return nil
	}
}

// WithDeviceType specifies the type of TPM device to use.  By default,
// the Linux device is used (/dev/tpmrm0).
func WithDeviceType(deviceType TpmDeviceType) TpmAdapterOptions {
	return func(tca *tpmCompositeAdapter) error {
		tca.deviceType = deviceType
		return nil
	}
}

// WithAkHandle specifies the ak handle to use during quote generation.  By default,
// it uses
func WithAkHandle(akHandle int) TpmAdapterOptions {
	return func(tca *tpmCompositeAdapter) error {
		if akHandle == 0 {
			akHandle = DefaultAkHandle
		}

		tca.akHandle = akHandle
		return nil
	}
}

// WithPcrSelections configures which PCRs to include during TPM quote generation.
func WithPcrSelections(selections string) TpmAdapterOptions {
	return func(tca *tpmCompositeAdapter) error {
		pcrSelections, err := parsePcrSelections(selections)
		if err != nil {
			return err
		}
		tca.pcrSelections = pcrSelections
		return nil
	}
}

func (tca *tpmCompositeAdapter) GetEvidenceIdentifier() string {
	return "tpm"
}

func (tca *tpmCompositeAdapter) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (interface{}, error) {
	tpm, err := New(
		WithTpmDeviceType(tca.deviceType),
		WithTpmOwnerAuth(tca.ownerAuth),
	)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open TPM")
	}

	// Create a sha256 hash of the verifier-nonce and user-data.
	nonceHash, err := createNonceHash(verifierNonce, userData)
	if err != nil {
		return nil, err
	}

	quote, signature, err := tpm.GetQuote(tca.akHandle, nonceHash, tca.pcrSelections...)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to get quote using AK handle 0x%x", tca.akHandle)
	}

	pcrs, err := tpm.GetPcrs(tca.pcrSelections...)
	if err != nil {
		return nil, err
	}

	tpmEvidence := struct {
		Q []byte                   `json:"quote"`
		S []byte                   `json:"signature"`
		P []byte                   `json:"pcrs"`
		U []byte                   `json:"user_data,omitempty"`
		V *connector.VerifierNonce `json:"verifier_nonce,omitempty"`
	}{
		Q: quote,
		S: signature,
		P: pcrs,
		U: userData,
		V: verifierNonce,
	}

	return &tpmEvidence, nil
}

func createNonceHash(verifierNonce *connector.VerifierNonce, userData []byte) ([]byte, error) {
	if verifierNonce == nil && len(userData) == 0 {
		return nil, nil
	}

	// Assume there are four possible combinations of verifier-nonce and user-data:
	// - None: no verifier-nonce or user-data (empty array)
	// - Just verifier-nonce (no user-data)
	// - Just user-data (no verifier-nonce)
	// - Both verifier-nonce and user-data
	//
	// The order will always be "verifier-nonce.Val" followed by "user-data".
	nonceBytes := []byte{}
	if verifierNonce != nil {
		nonceBytes = append(nonceBytes, verifierNonce.Val...)
		nonceBytes = append(nonceBytes, verifierNonce.Iat...)
	}

	if len(userData) > 0 {
		nonceBytes = append(nonceBytes, userData...)
	}

	h := sha256.New()
	_, err := h.Write(nonceBytes)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
