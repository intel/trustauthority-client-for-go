# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

ORGNAME := taas
APPNAME := golib
REPO := localhost:5000
SHELL := /bin/bash

GITCOMMIT := $(shell git rev-parse --short HEAD)
VERSION := v0.3.0
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)
PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" || "${no_proxy}" ]]; then echo 1; else echo 0; fi)
DOCKER_PROXY_FLAGS := ""
ifeq ($(PROXY_EXISTS),1)
    DOCKER_PROXY_FLAGS = --build-arg http_proxy="${http_proxy}" --build-arg https_proxy="${https_proxy}" --build-arg no_proxy="${no_proxy}"
else
    DOCKER_PROXY_FLAGS =
endif

makefile_path := $(realpath $(lastword $(MAKEFILE_LIST)))
makefile_dir := $(dir $(makefile_path))
OUTDIR := $(addprefix $(makefile_dir),out)
TMPDIR := $(addprefix $(makefile_dir),tmp)

.PHONY: all docker test clean help

all: docker

docker: docker.sgx.timestamp

docker.sgx.timestamp: docker.intel.timestamp docker.azure.timestamp

docker.intel.timestamp: Dockerfile.intel $(shell find $(makefile_dir) -type f -name '*.go' -or -name '*.h')
	pushd "$(makefile_dir)"
	docker build ${DOCKER_PROXY_FLAGS} -f $< --target final -t $(ORGNAME)/sgx-$(APPNAME)_intel:$(VERSION) .
	touch $@

test-image:
	docker build ${DOCKER_PROXY_FLAGS} -f Dockerfile.intel --target app -t $(ORGNAME)/$(APPNAME)-unit-test:$(VERSION) .

test: test-image
	docker run -i --rm $(ORGNAME)/$(APPNAME)-unit-test:$(VERSION) /bin/bash -c "CGO_CFLAGS_ALLOW='-f.*' GOOS=linux GOSUMDB=off /usr/local/go/bin/go test ./... -coverprofile=cover.out"

test-coverage: test-image	
	docker run -i --rm $(ORGNAME)/$(APPNAME)-unit-test:$(VERSION) /bin/bash -c "CGO_CFLAGS_ALLOW='-f.*' GOOS=linux GOSUMDB=off /usr/local/go/bin/go test ./... -coverprofile=cover.out; /usr/local/go/bin/go tool cover -func cover.out"

go-fmt: test-image
	docker run -i --rm $(ORGNAME)/$(APPNAME)-unit-test:$(VERSION) env GOOS=linux GOSUMDB=off /usr/local/go/bin/gofmt -l .

push: push-intel push-azure

push-commit: push-commit-intel push-commit-azure

push-commit-intel: push-intel
	docker tag $(ORGNAME)/sgx-$(APPNAME)_intel:$(VERSION) $(REPO)/$(ORGNAME)/sgx-$(APPNAME)_intel:$(VERSION)-$(GITCOMMIT)
	docker push $(REPO)/$(ORGNAME)/sgx-$(APPNAME)_intel:$(VERSION)-$(GITCOMMIT)

push-intel: docker.%.timestamp
	docker tag $(ORGNAME)/sgx-$(APPNAME)_intel:$(VERSION) $(REPO)/$(ORGNAME)/sgx-$(APPNAME)_intel:$(VERSION)
	docker push $(REPO)/$(ORGNAME)/sgx-$(APPNAME)_intel:$(VERSION)

clean:
	if pushd $(makefile_dir); then \
		rm -rf $(OUTDIR) $(TMPDIR); \
		rm -f docker.*.timestamp; \
	fi;

help:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$'
