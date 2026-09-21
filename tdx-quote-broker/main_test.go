/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	quotebroker "github.com/intel/trustauthority-client/go-tdx/quote_broker"
)

type staticQuoteGenerator struct {
	quote []byte
}

func (generator staticQuoteGenerator) GenerateQuote([]byte) ([]byte, error) {
	return generator.quote, nil
}

func TestRunServesAndRemovesSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "broker", "quote.sock")
	ctx, cancel := context.WithCancel(context.Background())
	runError := make(chan error, 1)
	go func() {
		runError <- run(ctx, socketPath, staticQuoteGenerator{quote: []byte("dcap-quote")})
	}()

	waitForSocket(t, socketPath)
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("failed to stat socket: %v", err)
	}
	if info.Mode().Perm() != 0o666 {
		t.Errorf("got socket mode %o, want 666", info.Mode().Perm())
	}

	quote, err := quotebroker.NewClient(socketPath).GetQuote(context.Background(), make([]byte, 64))
	if err != nil {
		t.Fatalf("quote request failed: %v", err)
	}
	if !bytes.Equal(quote, []byte("dcap-quote")) {
		t.Errorf("got quote %q, want %q", quote, "dcap-quote")
	}

	cancel()
	select {
	case err := <-runError:
		if err != nil {
			t.Fatalf("broker shutdown failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for broker shutdown")
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket still exists after shutdown: %v", err)
	}
}

func TestRunRejectsRelativeSocketPath(t *testing.T) {
	err := run(context.Background(), "quote.sock", staticQuoteGenerator{})
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("got error %v, want absolute path error", err)
	}
}

func TestRemoveStaleSocketRefusesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quote.sock")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatalf("failed to create regular file: %v", err)
	}

	err := removeStaleSocket(path)
	if err == nil || !strings.Contains(err.Error(), "refusing to remove non-socket") {
		t.Fatalf("got error %v, want non-socket error", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("regular file was removed: %v", err)
	}
}

func waitForSocket(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(socketPath); err == nil &&
			info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0o666 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for socket %s", socketPath)
}
