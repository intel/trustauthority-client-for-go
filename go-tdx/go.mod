// Copyright (c) 2022 Intel Corporation All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

module github.com/intel/amber/v1/client/tdx

go 1.20

require (
	github.com/intel/amber/v1/client v0.0.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.9.0
)

require (
	github.com/golang-jwt/jwt/v4 v4.4.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
)

replace github.com/intel/amber/v1/client => ../go-client
