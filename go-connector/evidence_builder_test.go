/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
)

func TestEvidenceBuilder(t *testing.T) {

	unConnector := MockConnector{}
	unConnector.On("GetNonce", mock.Anything).Return(GetNonceResponse{}, errors.New("error"))

	testData := []struct {
		name                 string
		adapter              CompositeEvidenceAdapter
		userData             []byte
		connector            Connector
		policyIds            []uuid.UUID
		tokenSigningAlg      JwtAlg
		policiesMustMatch    bool
		expectedEvidenceJson string
		errorExpected        bool
	}{
		{
			name:              "Positive Test",
			adapter:           &testCompositeEvidenceAdapter{},
			userData:          make([]byte, 8),
			policyIds:         []uuid.UUID{uuid.Nil},
			tokenSigningAlg:   RS256,
			policiesMustMatch: true,
			expectedEvidenceJson: `{
				"test":{
					"quote":"AAAAAAAAAAA=",
					"user_data":"AAAAAAAAAAA="
				},
				"policy_ids":["00000000-0000-0000-0000-000000000000"],
				"token_signing_alg":"RS256",
				"policy_must_match":true
			}`,
			errorExpected: false,
		},
		{
			name:                 "No Adapter Should Fail",
			adapter:              nil,
			expectedEvidenceJson: ``,
			errorExpected:        true,
		},
		{
			name:                 "Force Option Failure",
			adapter:              nil,
			connector:            &unConnector,
			expectedEvidenceJson: ``,
			errorExpected:        true,
		},
	}

	for _, td := range testData {
		t.Run(td.name, func(t *testing.T) {
			opts := []EvidenceBuilderOption{}

			if td.adapter != nil {
				opts = append(opts, WithEvidenceAdapter(td.adapter))
			}

			if td.userData != nil {
				opts = append(opts, WithUserData(td.userData))
			}

			if td.connector != nil {
				opts = append(opts, WithVerifierNonce(td.connector))
			}

			if td.policyIds != nil {
				opts = append(opts, WithPolicyIds(td.policyIds))
			}

			if td.tokenSigningAlg != "" {
				opts = append(opts, WithTokenSigningAlgorithm(td.tokenSigningAlg))
			}

			if td.policiesMustMatch {
				opts = append(opts, WithPoliciesMustMatch(td.policiesMustMatch))
			}

			eb, err := NewEvidenceBuilder(opts...)
			if td.errorExpected && err != nil {
				t.Logf("Passing test case: %q expected error %v", td.name, err)
				return
			} else if td.errorExpected && err == nil {
				t.Errorf("Expected error, but got nil")
				return
			} else if !td.errorExpected && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			evidence, err := eb.Build()
			if err != nil {
				t.Errorf("Unexpected build error: %v", err)
				return
			}

			// Converted the test's expected evidence JSON to an interface{} so it
			// can be compared with DeepEqual.
			var expectedEvidence interface{}
			if td.expectedEvidenceJson != "" {
				err = json.Unmarshal([]byte(td.expectedEvidenceJson), &expectedEvidence)
				if err != nil {
					t.Errorf("Invalid evidence JSON: %v", err)
					return
				}
			}

			// Convert the evidence to JSON and back so it can be compared with DeepEqual.
			b, err := json.Marshal(evidence)
			if err != nil {
				t.Errorf("Error marshalling evidence: %v", err)
			}
			fmt.Printf("For test data: %v\n", string(b))
			var jsonEvidence interface{}
			err = json.Unmarshal(b, &jsonEvidence)
			if err != nil {
				t.Errorf("Error marshalling evidence: %v", err)
				return
			}

			if !reflect.DeepEqual(jsonEvidence, expectedEvidence) {
				t.Errorf("Expected evidence %v, but got %v", expectedEvidence, jsonEvidence)
			}
		})
	}

}

type testCompositeEvidenceAdapter struct{}

func (m *testCompositeEvidenceAdapter) GetEvidenceIdentifier() string {
	return "test"
}

func (m *testCompositeEvidenceAdapter) GetEvidence(verifierNonce *VerifierNonce, userData []byte) (interface{}, error) {
	return &struct {
		Q []byte         `json:"quote"`
		U []byte         `json:"user_data,omitempty"`
		V *VerifierNonce `json:"verifier_nonce,omitempty"`
	}{
		Q: make([]byte, 8),
		U: userData,
		V: verifierNonce,
	}, nil
}
