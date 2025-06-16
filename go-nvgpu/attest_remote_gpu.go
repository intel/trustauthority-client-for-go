/*
 *   Copyright (c) 2025 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package nvgpu

import (
	"encoding/base64"
	"fmt"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

type RemoteEvidence struct {
	Certificate string
	Evidence    string
}

type GpuAttester struct {
	nvmlHandler nvmlHandler
}

func NewGpuAttester(h nvmlHandler) *GpuAttester {
	if h == nil {
		h = &defaultNVMLHandler{}
	}
	return &GpuAttester{
		nvmlHandler: h,
	}
}

// Use error constants for common error messages
var (
	ErrNVMLInitFailed     = fmt.Errorf("unable to initialize NVML")
	ErrCCNotEnabled       = fmt.Errorf("confidential computing is not enabled")
	ErrDeviceNotSupported = fmt.Errorf("device is not supported")
)

// GetRemoteEvidence collects attestation evidence and certificate chain from supported GPUs.
// It initializes NVML, checks for confidential computing support, and retrieves attestation
// reports and certificates for each supported device. The evidence and certificate are
// base64-encoded and returned as a slice of RemoteEvidence. Only one device is currently supported.
// Returns an error if any NVML operation fails or if the device is not supported.
func (g *GpuAttester) GetRemoteEvidence(nonce []byte) ([]RemoteEvidence, error) {
	ret := g.nvmlHandler.Init()
	defer g.nvmlHandler.Shutdown() // Always clean up NVML resources

	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("%w: %v", ErrNVMLInitFailed, nvml.ErrorString(ret))
	}

	computeState, ret := g.nvmlHandler.SystemGetConfComputeState()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("unable to get compute state: %v", nvml.ErrorString(ret))
	}
	if computeState.CcFeature != nvml.CC_SYSTEM_FEATURE_ENABLED {
		return nil, ErrCCNotEnabled
	}

	count, ret := g.nvmlHandler.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("unable to get device count: %v", nvml.ErrorString(ret))
	}

	if count > 1 {
		count = 1 // Currently only support one device
	}

	// Pre-allocate slice with expected capacity
	remoteEvidence := make([]RemoteEvidence, 0, 1)

	for i := 0; i < count; i++ {

		device, ret := g.nvmlHandler.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get device at index %d: %v", i, nvml.ErrorString(ret))
		}

		deviceArchitecture, ret := device.GetArchitecture()

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get architecture of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		if deviceArchitecture != nvml.DEVICE_ARCH_HOPPER {
			return nil, fmt.Errorf("device at index %d is not supported", i)
		}

		report, ret := device.GetConfComputeGpuAttestationReport(nonce)

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get attestation report of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		attestationReportData := report.AttestationReport[:report.AttestationReportSize]
		encodedAttestationReport := base64.StdEncoding.EncodeToString(attestationReportData)

		certificate, ret := device.GetConfComputeGpuCertificate()

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get certificate of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		attestationCertChainData := certificate.AttestationCertChain[:certificate.AttestationCertChainSize]
		certChain := NewCertChainFromPemData(attestationCertChainData)
		err := certChain.verify()
		if err != nil {
			return nil, fmt.Errorf("failed to verify certificate chain: %v", err)
		}

		encodedCertChain, err := certChain.encodeBase64()
		if err != nil {
			return nil, fmt.Errorf("failed to encode certificate chain: %v", err)
		}

		remoteEvidence = append(remoteEvidence, RemoteEvidence{Evidence: encodedAttestationReport, Certificate: encodedCertChain})
	}

	return remoteEvidence, nil
}
