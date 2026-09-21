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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
)

const (
	QuotePath     = "/v1/quote"
	HealthPath    = "/healthz"
	reportDataLen = 64
	maxAttempts   = 120
	retryDelay    = time.Second
)

type quoteRequest struct {
	ReportData string `json:"report_data"`
}

type quoteResponse struct {
	Quote string `json:"quote,omitempty"`
	Error string `json:"error,omitempty"`
}

type QuoteGenerator interface {
	GenerateQuote(reportData []byte) ([]byte, error)
}

type HealthChecker interface {
	HealthCheck() error
}

type ConfigFSQuoteGenerator struct{}

func (ConfigFSQuoteGenerator) HealthCheck() error {
	_, err := linuxtsm.MakeClient()
	return err
}

func (ConfigFSQuoteGenerator) GenerateQuote(reportData []byte) ([]byte, error) {
	if _, err := linuxtsm.MakeClient(); err != nil {
		return nil, err
	}

	response, err := linuxtsm.GetReport(&report.Request{
		InBlob:     reportData,
		GetAuxBlob: false,
	})
	if err != nil {
		return nil, err
	}

	return response.OutBlob, nil
}

type handler struct {
	generator QuoteGenerator
	active    chan struct{}
}

func NewHandler(generator QuoteGenerator) http.Handler {
	broker := &handler{generator: generator, active: make(chan struct{}, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc(HealthPath, broker.health)
	mux.HandleFunc(QuotePath, broker.quote)
	return mux
}

func (h *handler) health(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if checker, ok := h.generator.(HealthChecker); ok {
		if err := checker.HealthCheck(); err != nil {
			log.Printf("TDX quote broker health check failed: %v", err)
			http.Error(response, "quote generator unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *handler) quote(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		writeJSON(response, http.StatusMethodNotAllowed, quoteResponse{Error: "method not allowed"})
		return
	}

	request.Body = http.MaxBytesReader(response, request.Body, 4096)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var payload quoteRequest
	if err := decoder.Decode(&payload); err != nil {
		writeJSON(response, http.StatusBadRequest, quoteResponse{Error: "invalid request"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(response, http.StatusBadRequest, quoteResponse{Error: "invalid request"})
		return
	}

	reportData, err := base64.StdEncoding.DecodeString(payload.ReportData)
	if err != nil || len(reportData) != reportDataLen {
		writeJSON(response, http.StatusBadRequest, quoteResponse{Error: "report_data must be 64 bytes of base64"})
		return
	}

	if err := request.Context().Err(); err != nil {
		return
	}
	select {
	case h.active <- struct{}{}:
		defer func() { <-h.active }()
	default:
		response.Header().Set("Retry-After", "1")
		writeJSON(response, http.StatusServiceUnavailable, quoteResponse{Error: "quote generation already in progress"})
		return
	}

	quote, err := h.generator.GenerateQuote(reportData)
	if err != nil {
		log.Printf("TDX quote generation failed: %v", err)
		writeJSON(response, http.StatusInternalServerError, quoteResponse{Error: "quote generation failed"})
		return
	}
	if len(quote) == 0 {
		writeJSON(response, http.StatusInternalServerError, quoteResponse{Error: "quote generation returned an empty quote"})
		return
	}

	writeJSON(response, http.StatusOK, quoteResponse{Quote: base64.StdEncoding.EncodeToString(quote)})
}

func writeJSON(response http.ResponseWriter, status int, payload quoteResponse) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(payload); err != nil {
		log.Printf("Failed to write quote broker response: %v", err)
	}
}

type Client struct {
	httpClient *http.Client
}

func NewClient(socketPath string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}

	return &Client{httpClient: &http.Client{Transport: transport, Timeout: 2 * time.Minute}}
}

func (client *Client) GetQuote(ctx context.Context, reportData []byte) ([]byte, error) {
	if len(reportData) != reportDataLen {
		return nil, fmt.Errorf("report data must be %d bytes", reportDataLen)
	}

	payload, err := json.Marshal(quoteRequest{ReportData: base64.StdEncoding.EncodeToString(reportData)})
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		quote, retry, err := client.getQuote(ctx, payload)
		if err != nil || !retry {
			return quote, err
		}

		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, errors.New("quote broker remained busy")
}

func (client *Client) getQuote(ctx context.Context, payload []byte) ([]byte, bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+QuotePath, bytes.NewReader(payload))
	if err != nil {
		return nil, false, err
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()

	var result quoteResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil {
		return nil, false, err
	}
	if response.StatusCode == http.StatusServiceUnavailable && response.Header.Get("Retry-After") != "" {
		return nil, true, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("quote broker returned HTTP %d: %s", response.StatusCode, result.Error)
	}

	quote, err := base64.StdEncoding.DecodeString(result.Quote)
	if err != nil {
		return nil, false, fmt.Errorf("quote broker returned invalid quote encoding: %w", err)
	}
	if len(quote) == 0 {
		return nil, false, errors.New("quote broker returned an empty quote")
	}
	return quote, false, nil
}

func (client *Client) Health(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix"+HealthPath, nil)
	if err != nil {
		return err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("quote broker health check returned HTTP %d: %s", response.StatusCode, bytes.TrimSpace(message))
	}
	return nil
}
