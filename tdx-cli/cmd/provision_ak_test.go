/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package cmd

import (
	"testing"

	"github.com/stretchr/testify/mock"
)

func TestAkProvisioningPositive(t *testing.T) {

	mockTpm := &MockTpm{}
	mockTpm.On("CreateEK", mock.Anything).Return(nil)
	mockTpm.On("CreateAK", mock.Anything, mock.Anything).Return(nil)
	mockTpm.On("HandleExists", mock.Anything, mock.Anything).Return(false)
	mockTpm.On("ReadPublic", mock.Anything).Return(testAkPub, []byte{}, []byte{}, nil)
	mockTpm.On("GetEKCertificate", mock.Anything).Return(testCertificate, nil)
	mockTpm.On("ActivateCredential", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(testAesKey, nil)

	mockConnector := &MockConnector{}
	mockConnector.On("GetAKCertificate", mock.Anything, mock.Anything, mock.Anything).Return([]byte{}, []byte{}, testEncryptedAkCert, nil)

	_, err := provisionAk(testEkHandle, testAkHandle, mockConnector, mockTpm)
	if err != nil {
		t.Fatal(err)
	}
}
