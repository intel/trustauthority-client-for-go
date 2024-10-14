# Copyright(C) 2024 Intel Corporation. All Rights Reserved.
SHELL := /bin/bash
TPM_SIMULATOR_IMAGE_NAME := tpm-simulator
TPM_SIMULATOR_IMAGE_EXISTS := $(shell docker images -q $(TPM_SIMULATOR_IMAGE_NAME))
SIMULATOR_TEST_TARGETS := '.*'
MIN_UNIT_TEST_COVERAGE := 70

default: test

build-simulator:
# If the image does not exist, build it
ifeq ($(TPM_SIMULATOR_IMAGE_EXISTS),)
	@echo "Building $(TPM_SIMULATOR_IMAGE_NAME)..."
	docker build --build-arg http_proxy="${http_proxy}" --build-arg https_proxy="${https_proxy}" --build-arg no_proxy="${no_proxy}" -t $(TPM_SIMULATOR_IMAGE_NAME) .
else
	@echo "Image $(TPM_SIMULATOR_IMAGE_NAME) is already present and will not be rebuilt."
endif

# This target is helpful for writing unit tests (i.e., "make start-simulator", debug unit tests).
# It is also used in the "make test" target.
start-simulator: build-simulator
	@echo "Starting TPM simulator..."

	# Remove the simulator if it is already running
	docker rm -f $(TPM_SIMULATOR_IMAGE_NAME)

	# Run the simulator and go tests against it
	docker run -d --name $(TPM_SIMULATOR_IMAGE_NAME) -p 2321:2321 -p 2322:2322 $(TPM_SIMULATOR_IMAGE_NAME)

stop-simulator:
	@echo "Stopping TPM simulator..."
	docker rm -f $(TPM_SIMULATOR_IMAGE_NAME)

run-unit-tests:
	@echo "Running unit tests..."
	go test -v -run $(SIMULATOR_TEST_TARGETS) -coverprofile=cover.out -- -tpm-device=mssim
	go tool cover -func=cover.out && go tool cover -html=cover.out -o cover.html || exit 1

# default, wrapper target that starts the simulator, runs the unit tests, and stops the simulator
test: start-simulator run-unit-tests stop-simulator

test-coverage: test
	@COVERAGE=$(shell go tool cover -func cover.out | grep total | awk '{print $$3}' | sed 's/%//' | cut -d'.' -f1) && \
	echo "Unit Test Coverage: $$COVERAGE%" && \
	if [[ $$COVERAGE -lt $(MIN_UNIT_TEST_COVERAGE) ]]; then \
		echo "Unit test coverage must be above $(MIN_UNIT_TEST_COVERAGE)%"; \
		exit 1; \
	fi

clean:
	rm -f cover.out cover.html
	docker image rm -f $(TPM_SIMULATOR_IMAGE_NAME)