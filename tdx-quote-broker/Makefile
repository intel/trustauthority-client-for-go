# Copyright (c) 2026 Intel Corporation
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
.PHONY: test test-coverage clean

default: test

test:
	@echo "Running unit tests..."
	go test -v ./...

test-coverage:
	@echo "Running unit tests with coverage..."
	go test -v -coverprofile=cover.out ./...
	go tool cover -func=cover.out

clean:
	rm -f cover.out