/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"context"
	"fmt"
	"path/filepath"

	quotebroker "github.com/intel/trustauthority-client/go-tdx/quote_broker"
)

const QuoteBrokerSocketEnv = "TRUSTAUTHORITY_TDX_QUOTE_SOCKET"

type brokerQuoteProvider struct {
	client *quotebroker.Client
}

func newBrokerQuoteProvider(socketPath string) (cfsQuoteProvider, error) {
	if !filepath.IsAbs(socketPath) {
		return nil, fmt.Errorf("%s must contain an absolute path", QuoteBrokerSocketEnv)
	}
	return &brokerQuoteProvider{client: quotebroker.NewClient(socketPath)}, nil
}

func (provider *brokerQuoteProvider) getQuoteFromConfigFS(reportData []byte) ([]byte, error) {
	quote, err := provider.client.GetQuote(context.Background(), reportData)
	if err != nil {
		return nil, fmt.Errorf("TDX quote broker request failed: %w", err)
	}
	return quote, nil
}
