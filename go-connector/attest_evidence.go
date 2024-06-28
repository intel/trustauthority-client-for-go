/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (ctr *trustAuthorityConnector) AttestEvidence(evidence interface{}, requestId string) (AttestResponse, error) {
	var response AttestResponse
	url := fmt.Sprintf("%s%s", ctr.cfg.ApiUrl, attestEndpoint)

	requestBody, err := json.Marshal(evidence)
	if err != nil {
		return response, err
	}

	logrus.Debugf("REQUEST BODY: %s", string(requestBody))

	newRequest := func() (*http.Request, error) {
		return http.NewRequest(http.MethodPost, url, bytes.NewReader(requestBody))
	}

	var headers = map[string]string{
		headerXApiKey:     ctr.cfg.ApiKey,
		headerAccept:      mimeApplicationJson,
		headerContentType: mimeApplicationJson,
		HeaderRequestId:   requestId,
	}

	processResponse := func(resp *http.Response) error {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Failed to read body from %s: %s", url, err)
		}

		if resp.StatusCode != http.StatusOK {
			return errors.Errorf("Request returned %d: %q", resp.StatusCode, string(body))
		}

		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		err = dec.Decode(&response)
		if err != nil {
			return errors.Errorf("Failed to decode json from %s: %s", err, string(body))
		}
		return nil
	}

	if err := doRequest(*ctr.rclient, ctr.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
		return response, err
	}

	return response, nil
}
