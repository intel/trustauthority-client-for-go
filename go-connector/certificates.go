/*
 *   Copyright (c) 2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"fmt"
	"io"
	"net/http"

	"github.com/pkg/errors"
)

// GetTokenSigningCertificates is used to get Trust Authority attestation token signing certificates
func (connector *trustConnector) GetTokenSigningCertificates() ([]byte, error) {
	url := fmt.Sprintf("%s/certs", connector.cfg.BaseUrl)

	newRequest := func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, url, nil)
	}

	var headers = map[string]string{
		headerAccept: mimeApplicationJson,
	}

	var jwks []byte
	processResponse := func(resp *http.Response) error {
		var err error
		jwks, err = io.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Failed to read body from %s: %s", url, err)
		}
		return nil
	}

	if err := doRequest(*connector.rclient, connector.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
		return nil, err
	}

	return jwks, nil
}
