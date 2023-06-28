# Copyright (c) 2022 Intel Corporation All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
APPNAME := amber-cli
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := v0.1.0

all: clean cli test test-coverage

cli:
	env GOOS=linux GOSUMDB=off CGO_CFLAGS_ALLOW="-f.*" \
	go build -ldflags "-X github.com/intel/amber/v1/client/tdx-cli/cmd.Version=$(VERSION) -X github.com/intel/amber/v1/client/tdx-cli/cmd.BuildDate=$(GITCOMMITDATE) -X github.com/intel/amber/v1/client/tdx-cli/cmd.GitHash=$(GITCOMMIT)" -o ${APPNAME}

test:
	env GOOS=linux GOSUMDB=off CGO_CFLAGS_ALLOW="-f.*" \
	go test ./... --tags=test
test-coverage:
	env GOOS=linux GOSUMDB=off CGO_CFLAGS_ALLOW='-f.*' \
	go test ./... --tags=test -coverprofile=cover.out; go tool cover -func cover.out
clean:
	rm -rf ${APPNAME}
.PHONY: clean cli test test-coverage
