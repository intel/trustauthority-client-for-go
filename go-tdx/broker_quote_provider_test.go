/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"bytes"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	quotebroker "github.com/intel/trustauthority-client/go-tdx/quote_broker"
)

type brokerTestQuoteGenerator struct {
	reportData []byte
	quote      []byte
}

func (generator *brokerTestQuoteGenerator) GenerateQuote(reportData []byte) ([]byte, error) {
	generator.reportData = append([]byte(nil), reportData...)
	return generator.quote, nil
}

func TestBrokerQuoteProviderRoundTrip(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "quote.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen on test socket: %v", err)
	}

	generator := &brokerTestQuoteGenerator{quote: []byte("dcap-quote")}
	server := &http.Server{Handler: quotebroker.NewHandler(generator)}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
	})

	provider, err := newBrokerQuoteProvider(socketPath)
	if err != nil {
		t.Fatalf("failed to create broker provider: %v", err)
	}
	reportData := bytes.Repeat([]byte{0x5a}, 64)
	quote, err := provider.getQuoteFromConfigFS(reportData)
	if err != nil {
		t.Fatalf("broker quote request failed: %v", err)
	}
	if !bytes.Equal(generator.reportData, reportData) {
		t.Error("broker received different report data")
	}
	if !bytes.Equal(quote, generator.quote) {
		t.Errorf("got quote %q, want %q", quote, generator.quote)
	}
}

func TestNewBrokerQuoteProviderRejectsRelativePath(t *testing.T) {
	_, err := newBrokerQuoteProvider("quote.sock")
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("got error %v, want absolute path error", err)
	}
}
