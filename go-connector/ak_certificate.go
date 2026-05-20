/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package connector

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type akCertificateRequest struct {
	EkCertificateDer []byte `json:"ek_certificate_der"`
	AKTpmtPublic     []byte `json:"ak_tpmt_public"`
}

type akCertificateRequestResponse struct {
	CredentialBlob     []byte `json:"credential_blob"`
	Secret             []byte `json:"secret"`
	EncryptedAkCertDer []byte `json:"encrypted_ak_cert_der"`
}

const akProvisioningApiPath = "/ak-provisioning/v1/ak-certs"

func (connector *trustAuthorityConnector) GetAKCertificate(ekCert *x509.Certificate, akTpmtPublic []byte) ([]byte, []byte, []byte, error) {
	if ekCert == nil {
		return nil, nil, nil, errors.New("EK certificate cannot be nil")
	}

	if len(akTpmtPublic) == 0 {
		return nil, nil, nil, errors.New("The AK's TPMT_PUBLIC cannot be nil or empty")
	}

	akCertRequest := akCertificateRequest{
		AKTpmtPublic:     akTpmtPublic,
		EkCertificateDer: ekCert.Raw,
	}

	requestBody, err := json.Marshal(akCertRequest)
	if err != nil {
		return nil, nil, nil, err
	}

	logrus.Debugf("REQ: %s", string(requestBody))

	url := fmt.Sprintf("%s%s", connector.cfg.ApiUrl, akProvisioningApiPath)
	newRequest := func() (*http.Request, error) {
		return http.NewRequest(http.MethodPost, url, bytes.NewReader(requestBody))
	}

	var headers = map[string]string{
		headerXApiKey:     connector.cfg.ApiKey,
		headerAccept:      mimeApplicationJson,
		headerContentType: mimeApplicationJson,
		HeaderRequestId:   uuid.New().String(),
	}

	var response akCertificateRequestResponse
	processResponse := func(resp *http.Response) error {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Failed to read body from %s: %s", url, err)
		}

		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		err = dec.Decode(&response)
		if err != nil {
			return errors.Errorf("Failed to decode json from %s: %s", err, string(body))
		}
		return nil
	}

	if err := doRequest(connector.rclient, newRequest, nil, headers, processResponse); err != nil {
		return nil, nil, nil, err
	}

	return response.CredentialBlob, response.Secret, response.EncryptedAkCertDer, nil
}
