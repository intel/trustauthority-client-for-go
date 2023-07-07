/*
 *   Copyright (c) 2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package tdx

import (
	"reflect"
	"testing"
)

func TestNewEventLogParser(t *testing.T) {
	tests := []struct {
		name string
		want EventLogParser
	}{
		{
			name: "UEFI event log parser",
			want: &uefiEventLogParser{
				uefiTableFilePath:    CcelPath,
				uefiEventLogFilePath: CcelDataPath,
			},
		},
		{
			name: "File event log parser",
			want: &fileEventLogParser{file: "test"},
		},
	}
	for _, tt := range tests {
		if tt.name == "File event log parser" {
			uefiEventLogFile = "test"
		}
		t.Run(tt.name, func(t *testing.T) {
			if got := NewEventLogParser(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewEventLogParser() = %v, want %v", got, tt.want)
			}
		})
	}
}
