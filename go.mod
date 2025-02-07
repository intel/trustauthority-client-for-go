// Copyright (c) 2022 Intel Corporation
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

module github.com/intel/trustauthority-client

go 1.22.0

toolchain go1.22.3

require (
	github.com/canonical/go-tpm2 v1.7.6
	github.com/confidentsecurity/go-nvtrust v0.1.2
	github.com/goccy/go-json v0.10.2
	github.com/golang-jwt/jwt/v4 v4.5.1
	github.com/google/go-configfs-tsm v0.2.2
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-retryablehttp v0.7.7
	github.com/lestrrat-go/jwx/v2 v2.0.21
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/NVIDIA/go-nvml v0.12.4-0 // indirect
	github.com/canonical/go-sp800.108-kdf v0.0.0-20210314145419-a3359f2d21b9 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.5 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/NVIDIA/go-nvml => github.com/confidentsecurity/go-nvml v0.0.0-20250102214226-9a52cebf0382
