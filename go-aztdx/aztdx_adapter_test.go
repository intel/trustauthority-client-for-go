/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package aztdx

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/intel/trustauthority-client/go-tpm"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
)

func TestCompositeAdapterPositive(t *testing.T) {
	// create a mock TPM that returns azure runtime data
	tpmFactory := createHappyTpmFactory(nil)

	// create a test server that returns a TDX quote
	defer createTestQuoteServer(nil).Close()

	adapter, err := NewCompositeEvidenceAdapter(tpmFactory)
	if err != nil {
		t.Error(err)
	}

	_, err = adapter.GetEvidence(nil, nil)
	if err != nil {
		t.Error(err)
	}
}

func TestEvidenceAdapterPositive(t *testing.T) {
	// create a mock TPM that returns azure runtime data
	tpmFactory := createHappyTpmFactory(nil)

	// create a test server that returns a TDX quote
	defer createTestQuoteServer(nil).Close()

	adapter, err := NewAzureTdxAdapter(tpmFactory, nil)
	if err != nil {
		t.Error(err)
	}

	_, err = adapter.CollectEvidence(nil)
	if err != nil {
		t.Error(err)
	}
}

func TestEvidenceAdapterTpmError(t *testing.T) {
	// create a tpm factory that returns an error on "New"
	tpmFactory := &MockTpmFactory{}
	tpmFactory.On("New", mock.Anything, mock.Anything).Return(&MockTpm{}, errors.New("mock tpm error"))

	// create a test server that returns a TDX quote
	defer createTestQuoteServer(nil).Close()

	adapter, err := NewCompositeEvidenceAdapter(tpmFactory)
	if err != nil {
		t.Error(err)
	}

	_, err = adapter.GetEvidence(nil, nil)
	if err == nil {
		t.Error("Expected error from tpm factory failure")
	}
}

func TestEvidenceAdapterNvDefineError(t *testing.T) {
	// create a mock TPM that returns an error on NVDefine
	mockTpm := MockTpm{}
	mockTpm.On("NVExists", mock.Anything).Return(false)
	mockTpm.On("NVDefine", mock.Anything, mock.Anything).Return(errors.New("mock tpm error"))
	mockTpm.On("NVWrite", mock.Anything, mock.Anything).Return(nil)
	mockTpm.On("NVRead", mock.Anything).Return([]byte{}, nil)
	mockTpm.On("Close", mock.Anything).Return()
	tpmFactory := createHappyTpmFactory(&mockTpm)

	// create a test server that returns a TDX quote
	defer createTestQuoteServer(nil).Close()

	adapter, err := NewCompositeEvidenceAdapter(tpmFactory)
	if err != nil {
		t.Error(err)
	}

	_, err = adapter.GetEvidence(nil, nil)
	if err == nil {
		t.Error("Expected tpm error")
	}
}

func TestEvidenceAdapterNvWriteError(t *testing.T) {
	// create a mock TPM that returns an error on NVWrite
	mockTpm := MockTpm{}
	mockTpm.On("NVExists", mock.Anything).Return(true)
	mockTpm.On("NVDefine", mock.Anything, mock.Anything).Return(nil)
	mockTpm.On("NVWrite", mock.Anything, mock.Anything).Return(errors.New("tpm error"))
	mockTpm.On("NVRead", mock.Anything).Return([]byte{}, nil)
	mockTpm.On("Close", mock.Anything).Return()
	tpmFactory := createHappyTpmFactory(&mockTpm)

	// create a test server that returns a TDX quote
	defer createTestQuoteServer(nil).Close()

	adapter, err := NewCompositeEvidenceAdapter(tpmFactory)
	if err != nil {
		t.Error(err)
	}

	_, err = adapter.GetEvidence(nil, nil)
	if err == nil {
		t.Error("Expected tpm error")
	}
}

func TestEvidenceAdapterNvReadError(t *testing.T) {
	// create a mock TPM that returns an error on NVRead
	mockTpm := MockTpm{}
	mockTpm.On("NVExists", mock.Anything).Return(true)
	mockTpm.On("NVDefine", mock.Anything, mock.Anything).Return(nil)
	mockTpm.On("NVWrite", mock.Anything, mock.Anything).Return(nil)
	mockTpm.On("NVRead", mock.Anything).Return([]byte{}, errors.New("tpm error"))
	mockTpm.On("Close", mock.Anything).Return()
	tpmFactory := createHappyTpmFactory(&mockTpm)

	// create a test server that returns a TDX quote
	defer createTestQuoteServer(nil).Close()

	adapter, err := NewCompositeEvidenceAdapter(tpmFactory)
	if err != nil {
		t.Error(err)
	}

	_, err = adapter.GetEvidence(nil, nil)
	if err == nil {
		t.Error("Expected tpm error")
	}
}

func TestCompositeAdapterQuoteRequestFailure(t *testing.T) {
	// create a mock TPM that returns azure runtime data
	tpmFactory := createHappyTpmFactory(nil)

	// create a test server that returns a failure
	defer createTestQuoteServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/acc/tdquote" {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})).Close()

	adapter, err := NewCompositeEvidenceAdapter(tpmFactory)
	if err != nil {
		t.Error(err)
	}

	_, err = adapter.GetEvidence(nil, nil)
	if err == nil {
		t.Error("Expected request failure")
	}
}

func TestCompositeAdapterQuoteInvalidJson(t *testing.T) {
	// create a mock TPM that returns azure runtime data
	tpmFactory := createHappyTpmFactory(nil)

	// create a test server that returns a failure
	defer createTestQuoteServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/acc/tdquote" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"xyz": "abc"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})).Close()

	adapter, err := NewCompositeEvidenceAdapter(tpmFactory)
	if err != nil {
		t.Error(err)
	}

	_, err = adapter.GetEvidence(nil, nil)
	if err == nil {
		t.Error("Expected request failure")
	}
}

func TestCompositeAdapterQuoteBadBase64(t *testing.T) {
	// create a mock TPM that returns azure runtime data
	tpmFactory := createHappyTpmFactory(nil)

	// create a test server that returns a failure
	defer createTestQuoteServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/acc/tdquote" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"quote": "not base 64"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})).Close()

	adapter, err := NewCompositeEvidenceAdapter(tpmFactory)
	if err != nil {
		t.Error(err)
	}

	_, err = adapter.GetEvidence(nil, nil)
	if err == nil {
		t.Error("Expected request failure")
	}
}

func createTestQuoteServer(f http.HandlerFunc) *httptest.Server {
	// default succesful response
	if f == nil {
		f = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/acc/tdquote" {
				w.WriteHeader(http.StatusOK)
				response := fmt.Sprintf(`{"quote": "%s"}`, azureTdxReportB64)
				w.Write([]byte(response))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		})
	}

	testServer := httptest.NewServer(f)
	tdxReportUrl = testServer.URL // override azure url for unit tests
	return testServer
}

func createHappyTpmFactory(mockTpm *MockTpm) tpm.TpmFactory {
	azureRuntimeData, _ := base64.StdEncoding.DecodeString(azureRuntimeDataB64)

	var tpm *MockTpm
	if mockTpm == nil {
		tpm = &MockTpm{}
		tpm.On("NVExists", mock.Anything).Return(true)
		tpm.On("NVDefine", mock.Anything, mock.Anything).Return(nil)
		tpm.On("NVWrite", mock.Anything, mock.Anything).Return(nil)
		tpm.On("NVRead", mock.Anything).Return(azureRuntimeData, nil)
		tpm.On("Close", mock.Anything).Return()
	} else {
		tpm = mockTpm
	}

	mockFactory := MockTpmFactory{}
	mockFactory.On("New", mock.Anything, mock.Anything).Return(tpm, nil)
	return &mockFactory
}

const (
	azureRuntimeDataB64 = `SENMQQIAAACECQAAAgAAAAAAAAAAAAAAAAAAAAAAAACBAAAAAAAAAAAAAAAAAAAABwcYGgP/AAMAAAAAAAAAAA/nEJs3YeC7TdtbwyqJDqBiaM9b3SHOibWfHu2Nd+zJ2evH2qGccFKvMvJO+IvgAt1HukkFGcnonovk6R4vfhwLDJDMmmV1y0rGrYIgcxLfvfc90ZvX24Nde6S6QUqjPhi8NKDFrEPLglFkSnlpD3AzI80nAQDCtwhQALhDiZlhAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2Xo3/pJsAoGPmUYjYE3PDBHdVp7UExDIcfyLtprtUL/wEDAAAAAAAEAQcAAAAAAAAAAAAAAAAAl5DYmhAhDsaWinc87iygW1qpcwnzZyepaFJ75GBvwZ5vc6zONQlGydRqm/emP4QwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAQcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5xgGAAAAAAC7N5+Oc0p1WDJQn2FAP5nbIlinCgHhFypJnW02QQGwZ1RVtONyo1wfAGVB8t4NcVQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMQEAAABAAAABAAAAAEAAACwBAAAeyJrZXlzIjpbeyJraWQiOiJIQ0xBa1B1YiIsImtleV9vcHMiOlsic2lnbiJdLCJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4iOiJ1NjkxdWdBQm1Ua2RzMTNLdnlWRGZiOTdqV0tBc3pOdTcyd1VLdW1JOVN1U3JFMURJRk1kVGUtdjhvb2M3TE4xS210M1Z0RU9QaUtXczYxTjE4bE1MeVgtcERvWDJoR01pMnhuUEh2aGNWc0Q0SmFueVV3SFdCZkhkdHpLVC1YMmEzUFNnLTZJRzJqUHdGbzBiNE80MTlkdEltaTdiR3VnU1dMQU1Bd200UG1OZnRRcTVKaXlkTVlyTGoxb2MxUmdLMElZUmJFVVUxRGpyaHNKT3VHYkpSUWhCQWFlMG4wMTcxX0hDQXJtRzB3OHBsZzdFMXdLbm1Lb1RLTXFhUHNHSWc5a29ZbzhvXzA2alhBaE11SEx4NEVVMndDZ2Q3c1VuWklBWGJhanlfNHlhM2FDS1ZLd2NnNGI5VlJyUkdEX2pGLWRSSnIzb2tlakhEbG50dTVvYXcifSx7ImtpZCI6IkhDTEVrUHViIiwia2V5X29wcyI6WyJlbmNyeXB0Il0sImt0eSI6IlJTQSIsImUiOiJBUUFCIiwibiI6IjQwd25JQUFBdWM2eWpXZlhfaXk3ZWdtQ3BFUVBIT21iM25sVzJ3ZTNsRzdXY3phSjliblRlaEN4M3Q2d3MwSGl1ekVKNFdLc2E1R2l3NVRvdGhVSEZVNGZadllxb2pGT0E3dUNIUVBBRXpIMng3QmRIYlRpNGJWbW0wa1NsRUlXaHJVc2ZnYU1ibnA4TUJlTWNHczZIY3J4Q1MxWkRQajhiNmN2bzZ2eUtyT3lwUjFtRmxmY2k3Rkdnd3VvcTF6bU02TmV0dHA2ejRaUkxIOWlDWWhHRTZQSmM2VXpYaFZwZEpDbVE2RW1fTExXRHhuYWxlM1dtODd3V2xrU3FfaEdmZDhfOU41TVI4bUo2YlpqN2JZODRTRmJPWU9SSHRYdHVnam1sUjZaUC1QVjY3aVdkWGZyc3RTSVNpem5pZmVnblBLc2lscktzd0hFSFpINUFvZGg3dyJ9XSwidm0tY29uZmlndXJhdGlvbiI6eyJjb25zb2xlLWVuYWJsZWQiOnRydWUsInJvb3QtY2VydC10aHVtYnByaW50IjoiNm5aWm5ZYUpjNEtxVVpfeXZBLW11Y0ZkWU5vdXZsUG5JVG5OTVhzSGwtMCIsInNlY3VyZS1ib290Ijp0cnVlLCJ0cG0tZW5hYmxlZCI6dHJ1ZSwidHBtLXBlcnNpc3RlZCI6dHJ1ZSwidm1VbmlxdWVJZCI6IkQ2REE4RThELTU0MTAtNDcxNi1BMEM3LTJGQTkxRUE0QTg2NiJ9LCJ1c2VyLWRhdGEiOiJDRjgzRTEzNTdFRUZCOEJERjE1NDI4NTBENjZEODAwN0Q2MjBFNDA1MEI1NzE1REM4M0Y0QTkyMUQzNkNFOUNFNDdEMEQxM0M1RDg1RjJCMEZGODMxOEQyODc3RUVDMkY2M0I5MzFCRDQ3NDE3QTgxQTUzODMyN0FGOTI3REEzRSJ9AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`
	azureTdxReportB64   = `BAACAIEAAAAAAAAAk5pyM_ecTKmUCg2zlX8GBw63EL_H5YFouU_M5DIyGdAAAAAABAEHAAAAAAAAAAAAAAAAAJeQ2JoQIQ7Glop3PO4soFtaqXMJ82cnqWhSe-Rgb8Geb3OszjUJRsnUapv3pj-EMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADnGAYAAAAAALs3n45zSnVYMlCfYUA_mdsiWKcKAeEXKkmdbTZBAbBnVFW043KjXB8AZUHy3g1xVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABi8NKDFrEPLglFkSnlpD3AzI80nAQDCtwhQALhDiZlhAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADMEAAAHywHG5AZPVviRb4eZFtc8-Q7fs0E2O6Jot3uUPHCJpBqQ6qoT_1akZsmGU8j00Ls4yGu3MZTKwGAB80WCqEElE2QAXryh8OEJdtzz4TaOy3Zr0EguzzhH9rMCvqK4Vdh09XsSBHQUR2k8NZV6Cpbv-EhsRyn6QJft5vkw7n_1fsGAEYQAAAHBxgaA_8AAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVAAAAAAAAAOcAAAAAAAAA5aOntdgwwpU7mFNMbFmjo0_cNOkz9_WJjwqFzwiEa8oAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANyeKnxvlI8XR040p_xD7QMPfBVj8bq932NAyC4OVKjFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAi8uC9tsFezyNMmqtwGtLdwaoMMJ_zZjrOunNiNmLdsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAFCegPnIhreXixWmOzCRtrZc6XVnW7mTasnEcXz7ZLvyz-TkGXME-qrS1PZxWLZub055ilO51ZvzZYhvtS1sVIAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHwUAXg4AAC0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlFOFRDQ0JKYWdBd0lCQWdJVWRzNVgxM0xjQlB5RjlJU2tCNTZ4ajJHaEVtd3dDZ1lJS29aSXpqMEVBd0l3CmNERWlNQ0FHQTFVRUF3d1pTVzUwWld3Z1UwZFlJRkJEU3lCUWJHRjBabTl5YlNCRFFURWFNQmdHQTFVRUNnd1IKU1c1MFpXd2dRMjl5Y0c5eVlYUnBiMjR4RkRBU0JnTlZCQWNNQzFOaGJuUmhJRU5zWVhKaE1Rc3dDUVlEVlFRSQpEQUpEUVRFTE1Ba0dBMVVFQmhNQ1ZWTXdIaGNOTWpRd05URTNNRFF5TlRNd1doY05NekV3TlRFM01EUXlOVE13CldqQndNU0l3SUFZRFZRUUREQmxKYm5SbGJDQlRSMWdnVUVOTElFTmxjblJwWm1sallYUmxNUm93R0FZRFZRUUsKREJGSmJuUmxiQ0JEYjNKd2IzSmhkR2x2YmpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnUTJ4aGNtRXhDekFKQmdOVgpCQWdNQWtOQk1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTC9sClpFY3dqb2REU0FVeThPYjBNYVFDMDVDV0RYVkUzQjRLMGIwT0hwK1V4bW1IRVhSemkxSTZBa2greE5TZk11VUEKQ3RVRmdjN1ZsUkhIUFBCUVNMU2pnZ01NTUlJRENEQWZCZ05WSFNNRUdEQVdnQlNWYjEzTnZSdmg2VUJKeWRUMApNODRCVnd2ZVZEQnJCZ05WSFI4RVpEQmlNR0NnWHFCY2hscG9kSFJ3Y3pvdkwyRndhUzUwY25WemRHVmtjMlZ5CmRtbGpaWE11YVc1MFpXd3VZMjl0TDNObmVDOWpaWEowYVdacFkyRjBhVzl1TDNZMEwzQmphMk55YkQ5allUMXcKYkdGMFptOXliU1psYm1OdlpHbHVaejFrWlhJd0hRWURWUjBPQkJZRUZOZVVIVWxkazVkR2toaWcvMG9XOVd6TQo5NzlLTUE0R0ExVWREd0VCL3dRRUF3SUd3REFNQmdOVkhSTUJBZjhFQWpBQU1JSUNPUVlKS29aSWh2aE5BUTBCCkJJSUNLakNDQWlZd0hnWUtLb1pJaHZoTkFRMEJBUVFRUnd1Q1k5WFgvTU4rVElzT3ZjRW9MVENDQVdNR0NpcUcKU0liNFRRRU5BUUl3Z2dGVE1CQUdDeXFHU0liNFRRRU5BUUlCQWdFSE1CQUdDeXFHU0liNFRRRU5BUUlDQWdFSApNQkFHQ3lxR1NJYjRUUUVOQVFJREFnRUNNQkFHQ3lxR1NJYjRUUUVOQVFJRUFnRUNNQkFHQ3lxR1NJYjRUUUVOCkFRSUZBZ0VETUJBR0N5cUdTSWI0VFFFTkFRSUdBZ0VCTUJBR0N5cUdTSWI0VFFFTkFRSUhBZ0VBTUJBR0N5cUcKU0liNFRRRU5BUUlJQWdFRE1CQUdDeXFHU0liNFRRRU5BUUlKQWdFQU1CQUdDeXFHU0liNFRRRU5BUUlLQWdFQQpNQkFHQ3lxR1NJYjRUUUVOQVFJTEFnRUFNQkFHQ3lxR1NJYjRUUUVOQVFJTUFnRUFNQkFHQ3lxR1NJYjRUUUVOCkFRSU5BZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSU9BZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSVBBZ0VBTUJBR0N5cUcKU0liNFRRRU5BUUlRQWdFQU1CQUdDeXFHU0liNFRRRU5BUUlSQWdFTE1COEdDeXFHU0liNFRRRU5BUUlTQkJBSApCd0lDQXdFQUF3QUFBQUFBQUFBQU1CQUdDaXFHU0liNFRRRU5BUU1FQWdBQU1CUUdDaXFHU0liNFRRRU5BUVFFCkJnQ0Fid1VBQURBUEJnb3Foa2lHK0UwQkRRRUZDZ0VCTUI0R0NpcUdTSWI0VFFFTkFRWUVFT3gwZ3NpOTNqclUKajVyMnlGSjFBdE13UkFZS0tvWklodmhOQVEwQkJ6QTJNQkFHQ3lxR1NJYjRUUUVOQVFjQkFRSC9NQkFHQ3lxRwpTSWI0VFFFTkFRY0NBUUVBTUJBR0N5cUdTSWI0VFFFTkFRY0RBUUgvTUFvR0NDcUdTTTQ5QkFNQ0Ewa0FNRVlDCklRQ1FzLzRCT3YyOHZDNGlvVy9VbnN2VnNrdHQyRmkvc0FGQU9FVlB2ZzVCZGdJaEFOZFdjRnEzQS9GbjBqTWEKV09meHllQkcyaGZ4WDF1eS9Ya3FPV3NoM2lUTQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDbGpDQ0FqMmdBd0lCQWdJVkFKVnZYYzI5RytIcFFFbkoxUFF6emdGWEM5NVVNQW9HQ0NxR1NNNDlCQU1DCk1HZ3hHakFZQmdOVkJBTU1FVWx1ZEdWc0lGTkhXQ0JTYjI5MElFTkJNUm93R0FZRFZRUUtEQkZKYm5SbGJDQkQKYjNKd2IzSmhkR2x2YmpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnUTJ4aGNtRXhDekFKQmdOVkJBZ01Ba05CTVFzdwpDUVlEVlFRR0V3SlZVekFlRncweE9EQTFNakV4TURVd01UQmFGdzB6TXpBMU1qRXhNRFV3TVRCYU1IQXhJakFnCkJnTlZCQU1NR1VsdWRHVnNJRk5IV0NCUVEwc2dVR3hoZEdadmNtMGdRMEV4R2pBWUJnTlZCQW9NRVVsdWRHVnMKSUVOdmNuQnZjbUYwYVc5dU1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJHRnlZVEVMTUFrR0ExVUVDQXdDUTBFeApDekFKQmdOVkJBWVRBbFZUTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFTlNCLzd0MjFsWFNPCjJDdXpweHc3NGVKQjcyRXlER2dXNXJYQ3R4MnRWVExxNmhLazZ6K1VpUlpDbnFSN3BzT3ZncUZlU3hsbVRsSmwKZVRtaTJXWXozcU9CdXpDQnVEQWZCZ05WSFNNRUdEQVdnQlFpWlF6V1dwMDBpZk9EdEpWU3YxQWJPU2NHckRCUwpCZ05WSFI4RVN6QkpNRWVnUmFCRGhrRm9kSFJ3Y3pvdkwyTmxjblJwWm1sallYUmxjeTUwY25WemRHVmtjMlZ5CmRtbGpaWE11YVc1MFpXd3VZMjl0TDBsdWRHVnNVMGRZVW05dmRFTkJMbVJsY2pBZEJnTlZIUTRFRmdRVWxXOWQKemIwYjRlbEFTY25VOURQT0FWY0wzbFF3RGdZRFZSMFBBUUgvQkFRREFnRUdNQklHQTFVZEV3RUIvd1FJTUFZQgpBZjhDQVFBd0NnWUlLb1pJemowRUF3SURSd0F3UkFJZ1hzVmtpMHcraTZWWUdXM1VGLzIydWFYZTBZSkRqMVVlCm5BK1RqRDFhaTVjQ0lDWWIxU0FtRDV4a2ZUVnB2bzRVb3lpU1l4ckRXTG1VUjRDSTlOS3lmUE4rCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNqekNDQWpTZ0F3SUJBZ0lVSW1VTTFscWROSW56ZzdTVlVyOVFHemtuQnF3d0NnWUlLb1pJemowRUF3SXcKYURFYU1CZ0dBMVVFQXd3UlNXNTBaV3dnVTBkWUlGSnZiM1FnUTBFeEdqQVlCZ05WQkFvTUVVbHVkR1ZzSUVOdgpjbkJ2Y21GMGFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhDekFKCkJnTlZCQVlUQWxWVE1CNFhEVEU0TURVeU1URXdORFV4TUZvWERUUTVNVEl6TVRJek5UazFPVm93YURFYU1CZ0cKQTFVRUF3d1JTVzUwWld3Z1UwZFlJRkp2YjNRZ1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWc0lFTnZjbkJ2Y21GMAphVzl1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4Q3pBSkJnTlZCQVlUCkFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVDNm5Fd01ESVlaT2ovaVBXc0N6YUVLaTcKMU9pT1NMUkZoV0dqYm5CVkpmVm5rWTR1M0lqa0RZWUwwTXhPNG1xc3lZamxCYWxUVll4RlAyc0pCSzV6bEtPQgp1ekNCdURBZkJnTlZIU01FR0RBV2dCUWlaUXpXV3AwMGlmT0R0SlZTdjFBYk9TY0dyREJTQmdOVkhSOEVTekJKCk1FZWdSYUJEaGtGb2RIUndjem92TDJObGNuUnBabWxqWVhSbGN5NTBjblZ6ZEdWa2MyVnlkbWxqWlhNdWFXNTAKWld3dVkyOXRMMGx1ZEdWc1UwZFlVbTl2ZEVOQkxtUmxjakFkQmdOVkhRNEVGZ1FVSW1VTTFscWROSW56ZzdTVgpVcjlRR3prbkJxd3dEZ1lEVlIwUEFRSC9CQVFEQWdFR01CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRRXdDZ1lJCktvWkl6ajBFQXdJRFNRQXdSZ0loQU9XLzVRa1IrUzlDaVNEY05vb3dMdVBSTHNXR2YvWWk3R1NYOTRCZ3dUd2cKQWlFQTRKMGxySG9NcytYbzVvL3NYNk85UVd4SFJBdlpVR09kUlE3Y3ZxUlhhcUk9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
)
