//go:build !test

/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package sevsnp

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os/exec"
	"strings"

	"github.com/intel/trustauthority-client/go-connector"
	"github.com/pkg/errors"
)

const (
	SEVSNP_REPORT_OFFSET     = 32
	SEVSNP_REPORT_SIZE       = 1184
	RUNTIME_DATA_SIZE_OFFSET = 1232
	RUNTIME_DATA_OFFSET      = 1236
)

// AzureAdapter manages TDX Quote collection from Azure TDX platform
type azureSevSnpAdapter struct {
	uData []byte
}

// NewEvidenceAdapter returns a new Azure Adapter instance
func NewEvidenceAdapter(udata []byte) (connector.SevSnpEvidenceAdapter, error) {
	return &azureSevSnpAdapter{
		uData: udata,
	}, nil
}

// CollectEvidence is used to get TDX quote using Azure Quote Generation service
func (adapter *azureSevSnpAdapter) CollectEvidence(nonce []byte) (*connector.SevSnpEvidence, error) {

	var reportData []byte
	if nonce != nil || adapter.uData != nil {
		hash := sha512.New()
		_, err := hash.Write(nonce)
		if err != nil {
			return nil, err
		}
		_, err = hash.Write(adapter.uData)
		if err != nil {
			return nil, err
		}
		reportData = hash.Sum(nil)
	} else {
		// zeroize the runtime_data.user-data
		reportData = make([]byte, 64)
	}

	tpmReport, err := getTDReport(reportData)
	if err != nil {
		return nil, errors.Errorf("getTDReport returned err %v", err)
	}
	sevsnpReport := tpmReport[SEVSNP_REPORT_OFFSET : SEVSNP_REPORT_OFFSET+SEVSNP_REPORT_SIZE]

	runtimeDataSize := binary.LittleEndian.Uint32(tpmReport[RUNTIME_DATA_SIZE_OFFSET : RUNTIME_DATA_SIZE_OFFSET+4])
	runtimeData := tpmReport[RUNTIME_DATA_OFFSET : RUNTIME_DATA_OFFSET+runtimeDataSize]

	// validate the user-data(hash) in the evidence matches the user-data(hash) provided to the TPM
	var runtimeDataMap map[string]interface{}
	err = json.Unmarshal(runtimeData, &runtimeDataMap)
	if err != nil {
		return nil, errors.Errorf("invalid runtime_data %v", err)
	}
	userData, exists := runtimeDataMap["user-data"]
	if !exists {
		return nil, errors.Errorf("runtime_data doesn't include user-data %v", err)
	}
	userDataStr, ok := userData.(string)
	if !ok {
		return nil, errors.Errorf("user-data string assertion fail")
	}
	if !strings.EqualFold(userDataStr, hex.EncodeToString(reportData)) {
		return nil, errors.Errorf("The collected evidence is invalid")
	}

	return &connector.SevSnpEvidence{
		Report:      sevsnpReport,
		UserData:    adapter.uData,
		RuntimeData: runtimeData,
	}, nil
}

func getTDReport(reportData []byte) ([]byte, error) {

	// check if index 0x01400002 is defined or not
	_, err := exec.Command("tpm2_nvreadpublic", "0x01400002").Output()
	if err != nil {
		_, err = exec.Command("tpm2_nvdefine", "-C", "o", "0x01400002", "-s", "64").Output()
		if err != nil {
			return nil, err
		}
	}
	cmd := exec.Command("tpm2_nvwrite", "-C", "o", "0x1400002", "-i", "-")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, string(reportData))
	}()

	_, err = cmd.Output()
	if err != nil {
		return nil, err
	}

	tdReport, err := exec.Command("tpm2_nvread", "-C", "o", "0x01400001").Output()
	if err != nil {
		return nil, err
	}
	return tdReport, nil
}
