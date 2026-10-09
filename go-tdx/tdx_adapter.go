/*
 *   Copyright (c) 2022-2025 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"crypto/sha512"
	"errors"

	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/intel/trustauthority-client/go-connector"
)

// TdxAdapter manages TDX Quote collection from TDX enabled platform
type tdxAdapter struct {
	uData            []byte
	withCcel         bool
	cfsQuoteProvider cfsQuoteProvider
}

type compositeTdxEvidence struct {
	RuntimeData   []byte                   `json:"runtime_data"`
	Quote         []byte                   `json:"quote"`
	EventLog      []byte                   `json:"event_log,omitempty"`
	VerifierNonce *connector.VerifierNonce `json:"verifier_nonce,omitempty"`
}

// NewTdxAdapter returns a new TDX Adapter instance
func NewTdxAdapter(udata []byte, withCcel bool) (connector.EvidenceAdapter, error) {
	return &tdxAdapter{
		uData:            udata,
		withCcel:         withCcel,
		cfsQuoteProvider: &cfsQuoteProviderImpl{},
	}, nil
}

// CollectEvidence is used to get TDX quote using TDX Quote Generation service
func (adapter *tdxAdapter) CollectEvidence(nonce []byte) (*connector.Evidence, error) {

	hash := sha512.New()
	_, err := hash.Write(nonce)
	if err != nil {
		return nil, err
	}
	_, err = hash.Write(adapter.uData)
	if err != nil {
		return nil, err
	}
	reportData := hash.Sum(nil)

	quote, err := adapter.cfsQuoteProvider.getQuoteFromConfigFS(reportData)
	if err != nil {
		return nil, err
	}

	if len(quote) == 0 {
		return nil, errors.New("empty quote received from TDX Quote Generation Service")
	}

	var ccelBytes []byte
	if adapter.withCcel {
		ccelBytes, err = GetCcel()
		if err != nil {
			return nil, err
		}
	}

	return &connector.Evidence{
		Type:        connector.Tdx,
		Evidence:    quote,
		RuntimeData: adapter.uData,
		EventLog:    ccelBytes,
	}, nil
}

type cfsQuoteProvider interface {
	getQuoteFromConfigFS(reportData []byte) ([]byte, error)
}

type cfsQuoteProviderImpl struct{}

func (cp *cfsQuoteProviderImpl) getQuoteFromConfigFS(reportData []byte) ([]byte, error) {
	_, err := linuxtsm.MakeClient()
	if err != nil {
		return nil, err
	}

	req := &report.Request{
		InBlob:     reportData[:],
		GetAuxBlob: false,
	}
	resp, err := linuxtsm.GetReport(req)
	if err != nil {
		return nil, err
	}

	return resp.OutBlob, nil
}

func NewCompositeEvidenceAdapter(withCcel bool) (connector.CompositeEvidenceAdapter, error) {
	return &tdxAdapter{
		withCcel:         withCcel,
		cfsQuoteProvider: &cfsQuoteProviderImpl{},
	}, nil
}

func (adapter *tdxAdapter) GetEvidenceIdentifier() string {
	return "tdx"
}

func (adapter *tdxAdapter) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (interface{}, error) {
	adapter.uData = userData

	var nonce []byte
	if verifierNonce != nil {
		nonce = append(verifierNonce.Val, verifierNonce.Iat[:]...)
	}

	quote, err := adapter.CollectEvidence(nonce)
	if err != nil {
		return nil, err
	}

	return &compositeTdxEvidence{
		RuntimeData:   quote.RuntimeData,
		Quote:         quote.Evidence,
		EventLog:      quote.EventLog,
		VerifierNonce: verifierNonce,
	}, nil
}
