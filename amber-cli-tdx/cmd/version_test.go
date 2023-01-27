/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"fmt"
	"github.com/intel/amber/v1/client/tdx-cli/constants"
	"testing"
)

func TestGetVersion(t *testing.T) {
	Version = "1"
	GitHash = "abc1234"
	BuildDate = "01-01-1990"

	expected := fmt.Sprintf("%s\n", constants.RootCmd)
	expected = expected + fmt.Sprintf("Version: %s-%s\n", Version, GitHash)
	expected = expected + fmt.Sprintf("Build Date: %s\n", BuildDate)

	tests := []struct {
		name string
		want error
	}{
		{
			name: "Valid test",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getVersion(); got != tt.want {
				t.Errorf("GetVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
