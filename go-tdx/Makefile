# Copyright (c) 2024 Intel Corporation
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
SHELL := /bin/bash
MIN_UNIT_TEST_COVERAGE := 70 # KWT:  address tdx_adpater.go coverage

.PHONY: test
default: test

test:
	@echo "Running unit tests..."
	go test -v -coverprofile=cover.out
	go tool cover -func=cover.out && go tool cover -html=cover.out -o cover.html || exit 1

test-coverage: test
	@COVERAGE=$(shell go tool cover -func cover.out | grep total | awk '{print $$3}' | sed 's/%//' | cut -d'.' -f1) && \
	echo "Unit Test Coverage: $$COVERAGE%" && \
	if [[ $$COVERAGE -lt $(MIN_UNIT_TEST_COVERAGE) ]]; then \
		echo "Unit test coverage must be above $(MIN_UNIT_TEST_COVERAGE)%"; \
		exit 1; \
	fi

clean:
	rm -f cover.out cover.html