/*
 *   Copyright (c) 2022-2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package aztdx

import (
	"bytes"
	"encoding/binary"
	"encoding/json"

	"github.com/pkg/errors"
)

const (
	azTdReportOffset        = 32
	azTdReportSize          = 1024
	azRuntimeDataSizeOffset = 1232
)

// azRuntimeData is an internal structure that holds runtime data from Azure VM
// and provides utilities for parsing its data.
type azRuntimeData struct {
	tdReportBytes    []byte
	runtimeJsonBytes []byte
}

// Example data from Azure...
//
//	{
//		"keys": [
//		  {
//			"e": "AQAB",
//			"key_ops": [
//			  "sign"
//			],
//			"kid": "HCLAkPub",
//			"kty": "RSA",
//			"n": "skofOAAA6buG4CQjuyV0J2hx4FwQIEtyKjUNsfu2ykSDlCjPiKobJhq9x2eTsnhKgzseF1b_48EsVRZ7zS5-V9sO3tSiwFTq2uD67yCyYh63dffGlzTNGDnAPV_3BctT2MtndC9R63BCWxqVt36-P3idSeYSVU3Q4b_j78EOdEJIkn8XS4g53u7z_xM7rmNl0iONL6SuRTpS2-L0w3qtrY_KH6xt_c4_O7aqMmr1kf1PckTY6Z73Q81cJy4Wba4oJhOGIYcULw017Xp4iiKewBi7Zoo5r3l040BJNFzt4RVAHyty4KJVcAFV_AJjkQXqeb2dXXLJieenkUiAT4vlwQ"
//		  },
//		  {
//			"e": "AQAB",
//			"key_ops": [
//			  "encrypt"
//			],
//			"kid": "HCLEkPub",
//			"kty": "RSA",
//			"n": "olKahAAAficIyowZ7cS_D0L4D_CeLr_ZINvEAbBoyKivlAG6_8IbxOjue7k57XlP3FnM1WFtjaw2G7P7LdztBgE1vFesMpyBBQ4YmyUuQs-E4sPIEsD7WeOJHB_L22v2mLxPwhS6McgvOYQ_DER0JbWScln-So6xvWukBqU0TOBuBp2putTeQdZsKR_9UuLfTQsH3FyeciFPz0KOZ0qnFmQ455iBK_ADAT1Ebfu22MpCjEQ62-Q1PRVS-aoP6DAnMqxrwDPoCAFdGuljBVJIUVR2ubsS4NfChirlDzOYcX5DOcea-TUvQ8juWqqf25LHjSNYG3DUu4fkMhEO_el6Gw"
//		  }
//		],
//		"user-data": "9BB304372F8CF113551FEFDC481D132709C44596F791E0D565C223B6BDC18F53172EAB615DADF39AB3B936E06A2A0B570A05145C1CD5008E56E033C666C2ED2C",
//		"vm-configuration": {
//		  "console-enabled": true,
//		  "root-cert-thumbprint": "6nZZnYaJc4KqUZ_yvA-mucFdYNouvlPnITnNMXsHl-0",
//		  "secure-boot": true,
//		  "tpm-enabled": true,
//		  "tpm-persisted": true,
//		  "vmUniqueId": "A84E0112-30B3-4F18-8083-4B5ABED580A5"
//		}
//	  }
type azRuntimeJson struct {
	Keys            []azKey           `json:"keys"`
	UserData        string            `json:"user-data"`
	VmConfiguration azVmConfiguration `json:"vm-configuration"`
}

type azKey struct {
	E      string   `json:"e"`
	KeyOps []string `json:"key_ops"`
	Kid    string   `json:"kid"`
	Kty    string   `json:"kty"`
	N      string   `json:"n"`
}

type azVmConfiguration struct {
	ConsoleEnabled     bool   `json:"console-enabled"`
	RootCertThumbprint string `json:"root-cert-thumbprint"`
	SecureBoot         bool   `json:"secure-boot"`
	TpmEnabled         bool   `json:"tpm-enabled"`
	TpmPersisted       bool   `json:"tpm-persisted"`
	VmUniqueId         string `json:"vmUniqueId"`
}

func newAzRuntimeData(data []byte) (*azRuntimeData, error) {
	if len(data) == 0 || len(data) < azRuntimeDataSizeOffset {
		return nil, errors.Errorf("Invalid runtime data size %d", len(data))
	}

	runtimeDataSize := binary.LittleEndian.Uint32(data[azRuntimeDataSizeOffset : azRuntimeDataSizeOffset+4])
	if len(data) < int(runtimeDataSize) {
		return nil, errors.Errorf("Invalid runtime data size %d", len(data))
	}

	return &azRuntimeData{
		tdReportBytes:    data[azTdReportOffset : azTdReportOffset+azTdReportSize],
		runtimeJsonBytes: data[azRuntimeDataSizeOffset+4 : azRuntimeDataSizeOffset+4+runtimeDataSize],
	}, nil
}

func (azrtd *azRuntimeData) RuntimeData() (*azRuntimeJson, error) {
	var azRuntimeJson azRuntimeJson
	decoder := json.NewDecoder(bytes.NewReader(azrtd.runtimeJsonBytes))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&azRuntimeJson)
	if err != nil {
		return nil, err
	}

	return &azRuntimeJson, nil
}
