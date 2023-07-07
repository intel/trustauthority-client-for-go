/*
 *   Copyright (c) 2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"testing"
)

func TestFileEventLogParserGetEventLogs(t *testing.T) {
	type fields struct {
		file string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Valid event log file as input",
			fields: fields{
				file: "test/resources/event_log.bin",
			},
			wantErr: false,
		},
		{
			name: "Non existing event log file as input",
			fields: fields{
				file: "test/resources/acpi",
			},
			wantErr: true,
		},
		{
			name: "Invalid event log file as input",
			fields: fields{
				file: ccelPath,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := &fileEventLogParser{
				file: tt.fields.file,
			}
			_, err := parser.GetEventLogs()
			if (err != nil) != tt.wantErr {
				t.Errorf("fileEventLogParser.GetEventLogs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
