# Copyright (c) 2022 Intel Corporation
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
APPNAME := trustauthority-cli
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := v1.5.0

cli:
	CGO_ENABLED=1 CGO_CFLAGS="-O2 -D_FORTIFY_SOURCE=2" go build -buildmode=pie -trimpath -ldflags "-s -linkmode=external -extldflags -Wl,-O1,-z,relro,-z,now \
	    -X github.com/intel/trustauthority-client/tdx-cli/cmd.Version=$(VERSION) -X github.com/intel/trustauthority-client/tdx-cli/cmd.BuildDate=$(GITCOMMITDATE) \
	    -X github.com/intel/trustauthority-client/tdx-cli/cmd.GitHash=$(GITCOMMIT)" -o ${APPNAME}

test:
	go test ./... --tags=test
test-coverage:
	go test ./... --tags=test -coverprofile=cover.out; go tool cover -func cover.out
clean:
	rm -rf ${APPNAME}
all: clean cli test test-coverage
.PHONY: clean cli test test-coverage
