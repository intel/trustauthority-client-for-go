/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	quotebroker "github.com/intel/trustauthority-client/go-tdx/quote_broker"
)

const defaultSocketPath = "/run/tdx-quote-broker/quote.sock"

func main() {
	socketPath := flag.String("socket", defaultSocketPath, "Unix socket used to serve quote requests")
	healthcheck := flag.Bool("healthcheck", false, "Check the quote broker and exit")
	flag.Parse()
	if *healthcheck {
		if err := quotebroker.NewClient(*socketPath).Health(context.Background()); err != nil {
			log.Fatal(err)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *socketPath, quotebroker.ConfigFSQuoteGenerator{}); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, socketPath string, generator quotebroker.QuoteGenerator) error {
	if !filepath.IsAbs(socketPath) {
		return errors.New("socket path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	if err := removeStaleSocket(socketPath); err != nil {
		return err
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)
	if err := os.Chmod(socketPath, 0o666); err != nil {
		return fmt.Errorf("set socket permissions: %w", err)
	}

	server := &http.Server{
		Handler:           quotebroker.NewHandler(generator),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	serverError := make(chan error, 1)
	go func() {
		serverError <- server.Serve(listener)
	}()

	log.Printf("TDX quote broker listening on %s", socketPath)
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shut down quote broker: %w", err)
		}
		return nil
	case err := <-serverError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve quote requests: %w", err)
	}
}

func removeStaleSocket(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect socket path: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket path %s", socketPath)
	}
	if err := os.Remove(socketPath); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	return nil
}
