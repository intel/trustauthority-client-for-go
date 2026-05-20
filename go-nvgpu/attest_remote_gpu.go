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
	Certificate     string
	Evidence        string
	FirmwareVersion string
	Arch            string
}

// archToString maps an nvml.DeviceArchitecture value to its lowercase string name.
func archToString(arch nvml.DeviceArchitecture) string {
	switch arch {
	case nvml.DEVICE_ARCH_KEPLER:
		return "kepler"
	case nvml.DEVICE_ARCH_MAXWELL:
		return "maxwell"
	case nvml.DEVICE_ARCH_PASCAL:
		return "pascal"
	case nvml.DEVICE_ARCH_VOLTA:
		return "volta"
	case nvml.DEVICE_ARCH_TURING:
		return "turing"
	case nvml.DEVICE_ARCH_AMPERE:
		return "ampere"
	case nvml.DEVICE_ARCH_ADA:
		return "ada"
	case nvml.DEVICE_ARCH_HOPPER:
		return "hopper"
	case nvml.DEVICE_ARCH_BLACKWELL:
		return "blackwell"
	default:
		return "unknown"
	}
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

// GetRemoteEvidence collects attestation evidence and certificate chain from all supported GPUs.
// It initializes NVML, checks for confidential computing support, and retrieves attestation
// reports and certificates for each supported device. Only Hopper and Blackwell architectures
// are supported; unsupported devices cause an immediate error. The attestation report and
// certificate chain are base64-encoded and returned as a slice of RemoteEvidence.
// Returns an error if any NVML operation fails, if the device is not supported, or if
// certificate chain verification fails.
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

	// Pre-allocate slice with expected capacity
	remoteEvidence := make([]RemoteEvidence, 0, count)

	for i := 0; i < count; i++ {

		device, ret := g.nvmlHandler.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get device at index %d: %v", i, nvml.ErrorString(ret))
		}

		deviceArchitecture, ret := device.GetArchitecture()

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get architecture of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		if deviceArchitecture != nvml.DEVICE_ARCH_HOPPER && deviceArchitecture != nvml.DEVICE_ARCH_BLACKWELL {
			return nil, fmt.Errorf("%w: device at index %d (arch %s) is not supported", ErrDeviceNotSupported, i, archToString(deviceArchitecture))
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

		remoteEvidence = append(remoteEvidence, RemoteEvidence{Evidence: encodedAttestationReport, Certificate: encodedCertChain, Arch: archToString(deviceArchitecture)})
	}

	return remoteEvidence, nil
}
