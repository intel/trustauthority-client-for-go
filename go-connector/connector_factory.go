/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package connector

// ConnectorFactory is an interface for instantiating Connector
// objects.
type ConnectorFactory interface {
	NewConnector(config *Config) (Connector, error)
}

// NewConnectorFactory returns a default instance of ConnectorFactory
// that will communicate with a remote instance of Intel Trust Authority.
func NewConnectorFactory() ConnectorFactory {
	return &connectorFactory{}
}

type connectorFactory struct{}

func (c *connectorFactory) NewConnector(config *Config) (Connector, error) {
	return New(config)
}
