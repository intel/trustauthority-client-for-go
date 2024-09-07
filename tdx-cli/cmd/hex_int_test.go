/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package cmd

import (
	"testing"
)

func TestHexIntPositive(t *testing.T) {
	hi := HexInt(0)

	err := hi.UnmarshalJSON([]byte(`"00000001"`))
	if err != nil {
		t.Fatal()
	}

	if int(hi) != 1 {
		t.Fatal()
	}
}

func TestHexIntEmptyString(t *testing.T) {
	hi := HexInt(1)

	err := hi.UnmarshalJSON([]byte(`""`))
	if err != nil {
		t.Fatal()
	}

	if int(hi) != 0 {
		t.Fatal()
	}
}

func TestHexIntEmptyBytes(t *testing.T) {
	hi := HexInt(1)

	err := hi.UnmarshalJSON([]byte{})
	if err != nil {
		t.Fatal()
	}

	if int(hi) != 0 {
		t.Fatal()
	}
}

func TestHexIntNilBytes(t *testing.T) {
	hi := HexInt(1)

	err := hi.UnmarshalJSON(nil)
	if err != nil {
		t.Fatal()
	}

	if int(hi) != 0 {
		t.Fatal()
	}
}

func TestHexIntNotHexIsError(t *testing.T) {
	hi := HexInt(1)

	err := hi.UnmarshalJSON([]byte(`"XXXX"`))
	if err == nil {
		t.Fatal()
	}
}
