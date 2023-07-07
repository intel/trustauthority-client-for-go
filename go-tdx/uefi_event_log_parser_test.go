/*
 *   Copyright (c) 2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"os"
	"testing"
)

const (
	ccelPath       = "test/resources/CCEL.bin"
	ccelDataPath   = "test/resources/CCEL.data.bin"
	ccelInvalidSig = "test/resources/CCEL.invalid.sig"
	ccelInvalidLen = "test/resources/CCEL.invalid.len"
)

var invalidSig = []byte{'C', 'C', 'L', 'E', 56, 0, 0, 0}
var invalidLen = []byte{'C', 'C', 'E', 'L', 48, 0, 0, 0}

func TestUefiEventLogParserGetEventLogs(t *testing.T) {
	_ = os.WriteFile(ccelInvalidSig, invalidSig, 0600)
	defer os.Remove(ccelInvalidSig)

	_ = os.WriteFile(ccelInvalidLen, invalidLen, 0600)
	defer os.Remove(ccelInvalidLen)

	type fields struct {
		ccelAcpiTableFilePath string
		uefiEventLogFilePath  string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Create event log using path provided",
			fields: fields{
				ccelAcpiTableFilePath: ccelPath,
				uefiEventLogFilePath:  ccelDataPath,
			},
			wantErr: false,
		},
		{
			name: "Non existing acpi table file path",
			fields: fields{
				ccelAcpiTableFilePath: "test/resources/acpi",
				uefiEventLogFilePath:  ccelDataPath,
			},
			wantErr: true,
		},
		{
			name: "Non existing uefi event log file path",
			fields: fields{
				ccelAcpiTableFilePath: ccelPath,
				uefiEventLogFilePath:  "test/resources/acpi/data",
			},
			wantErr: true,
		},
		{
			name: "Invalid uefi event log file path",
			fields: fields{
				ccelAcpiTableFilePath: ccelPath,
				uefiEventLogFilePath:  ccelPath,
			},
			wantErr: true,
		},
		{
			name: "Invalid signature in acpi table",
			fields: fields{
				ccelAcpiTableFilePath: ccelInvalidSig,
				uefiEventLogFilePath:  ccelDataPath,
			},
			wantErr: true,
		},
		{
			name: "Invalid length in acpi table",
			fields: fields{
				ccelAcpiTableFilePath: ccelInvalidLen,
				uefiEventLogFilePath:  ccelDataPath,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := &uefiEventLogParser{
				uefiTableFilePath:    tt.fields.ccelAcpiTableFilePath,
				uefiEventLogFilePath: tt.fields.uefiEventLogFilePath,
			}
			_, err := parser.GetEventLogs()
			if (err != nil) != tt.wantErr {
				t.Errorf("uefiEventLogParser.GetEventLogs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
