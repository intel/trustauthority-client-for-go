/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package quotebroker

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type testQuoteGenerator struct {
	reportData []byte
	quote      []byte
	err        error
}

type healthCheckGenerator struct {
	*testQuoteGenerator
	healthError error
}

func (generator *healthCheckGenerator) HealthCheck() error {
	return generator.healthError
}

func (generator *testQuoteGenerator) GenerateQuote(reportData []byte) ([]byte, error) {
	generator.reportData = append([]byte(nil), reportData...)
	return generator.quote, generator.err
}

func TestClientRoundTrip(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "quote.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen on test socket: %v", err)
	}

	generator := &testQuoteGenerator{quote: bytes.Repeat([]byte{0xa5}, 8000)}
	server := &http.Server{Handler: NewHandler(generator)}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
	})

	reportData := bytes.Repeat([]byte{0x5a}, reportDataLen)
	quote, err := NewClient(socketPath).GetQuote(context.Background(), reportData)
	if err != nil {
		t.Fatalf("quote request failed: %v", err)
	}
	if !bytes.Equal(generator.reportData, reportData) {
		t.Error("broker received different report data")
	}
	if !bytes.Equal(quote, generator.quote) {
		t.Errorf("got quote %q, want %q", quote, generator.quote)
	}
	if err := NewClient(socketPath).Health(context.Background()); err != nil {
		t.Fatalf("health check failed: %v", err)
	}
}

func TestClientRejectsInvalidReportDataLength(t *testing.T) {
	_, err := NewClient("/unused").GetQuote(context.Background(), make([]byte, reportDataLen-1))
	if err == nil || !strings.Contains(err.Error(), "must be 64 bytes") {
		t.Fatalf("got error %v, want report data length error", err)
	}
}

func TestClientRetriesBusyBroker(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "quote.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen on test socket: %v", err)
	}

	attempts := 0
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		attempts++
		if attempts == 1 {
			response.Header().Set("Retry-After", "1")
			writeJSON(response, http.StatusServiceUnavailable, quoteResponse{Error: "busy"})
			return
		}
		writeJSON(response, http.StatusOK, quoteResponse{Quote: base64.StdEncoding.EncodeToString([]byte("dcap-quote"))})
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
	})

	quote, err := NewClient(socketPath).GetQuote(context.Background(), make([]byte, reportDataLen))
	if err != nil {
		t.Fatalf("quote request failed: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("got %d attempts, want 2", attempts)
	}
	if !bytes.Equal(quote, []byte("dcap-quote")) {
		t.Errorf("got quote %q, want %q", quote, "dcap-quote")
	}
}

func TestHealth(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, HealthPath, nil)
	response := httptest.NewRecorder()
	NewHandler(&testQuoteGenerator{}).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("got HTTP %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestHealthReportsUnavailableGenerator(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, HealthPath, nil)
	response := httptest.NewRecorder()
	generator := &healthCheckGenerator{
		testQuoteGenerator: &testQuoteGenerator{},
		healthError:        errors.New("configfs unavailable"),
	}
	NewHandler(generator).ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("got HTTP %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestQuoteRejectsConcurrentRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	generator := QuoteGeneratorFunc(func([]byte) ([]byte, error) {
		close(started)
		<-release
		return []byte("dcap-quote"), nil
	})
	handler := NewHandler(generator)
	body := `{"report_data":"` + base64.StdEncoding.EncodeToString(make([]byte, reportDataLen)) + `"}`

	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		request := httptest.NewRequest(http.MethodPost, QuotePath, strings.NewReader(body))
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}()
	<-started

	request := httptest.NewRequest(http.MethodPost, QuotePath, strings.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Errorf("got HTTP %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if response.Header().Get("Retry-After") != "1" {
		t.Error("missing Retry-After header")
	}

	close(release)
	waitGroup.Wait()
}

func TestQuoteDoesNotGenerateForCanceledRequest(t *testing.T) {
	generated := false
	generator := QuoteGeneratorFunc(func([]byte) ([]byte, error) {
		generated = true
		return []byte("dcap-quote"), nil
	})
	body := `{"report_data":"` + base64.StdEncoding.EncodeToString(make([]byte, reportDataLen)) + `"}`
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, QuotePath, strings.NewReader(body)).WithContext(ctx)

	NewHandler(generator).ServeHTTP(httptest.NewRecorder(), request)
	if generated {
		t.Error("quote generation ran for a canceled request")
	}
}

type QuoteGeneratorFunc func(reportData []byte) ([]byte, error)

func (generate QuoteGeneratorFunc) GenerateQuote(reportData []byte) ([]byte, error) {
	return generate(reportData)
}

func TestQuoteRejectsInvalidRequests(t *testing.T) {
	validReportData := base64.StdEncoding.EncodeToString(make([]byte, reportDataLen))
	tests := []struct {
		name   string
		method string
		body   string
		status int
	}{
		{name: "method", method: http.MethodGet, status: http.StatusMethodNotAllowed},
		{name: "invalid JSON", method: http.MethodPost, body: "{", status: http.StatusBadRequest},
		{name: "unknown field", method: http.MethodPost, body: `{"report_data":"` + validReportData + `","extra":true}`, status: http.StatusBadRequest},
		{name: "trailing JSON", method: http.MethodPost, body: `{"report_data":"` + validReportData + `"}{}`, status: http.StatusBadRequest},
		{name: "invalid base64", method: http.MethodPost, body: `{"report_data":"!"}`, status: http.StatusBadRequest},
		{name: "wrong length", method: http.MethodPost, body: `{"report_data":"AA=="}`, status: http.StatusBadRequest},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, QuotePath, strings.NewReader(test.body))
			response := httptest.NewRecorder()
			NewHandler(&testQuoteGenerator{}).ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("got HTTP %d, want %d", response.Code, test.status)
			}
		})
	}
}

func TestQuoteHandlesGeneratorFailures(t *testing.T) {
	reportData := base64.StdEncoding.EncodeToString(make([]byte, reportDataLen))
	tests := []struct {
		name      string
		generator *testQuoteGenerator
	}{
		{name: "error", generator: &testQuoteGenerator{err: errors.New("configfs failed")}},
		{name: "empty quote", generator: &testQuoteGenerator{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, QuotePath, strings.NewReader(`{"report_data":"`+reportData+`"}`))
			response := httptest.NewRecorder()
			NewHandler(test.generator).ServeHTTP(response, request)

			if response.Code != http.StatusInternalServerError {
				t.Fatalf("got HTTP %d, want %d", response.Code, http.StatusInternalServerError)
			}
		})
	}
}
