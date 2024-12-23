# Copyright (c) 2024 Intel Corporation
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
.PHONY: test-coverage test

all: test-coverage

TEST_PACKAGES =  go-aztdx \
			go-connector \
			go-tdx \
			go-tpm \
			tdx-cli

test-coverage: $(patsubst %, %-test-coverage, $(TEST_PACKAGES))
test: $(patsubst %, %-test, $(TEST_PACKAGES))

%-test:
	make -C $* test

%-test-coverage:
	make -C $* test-coverage

