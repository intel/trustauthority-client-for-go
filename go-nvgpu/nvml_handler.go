/*
 *   Copyright (c) 2025 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package nvgpu

import (
	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

// nvmlHandler defines the interface for NVML handler implementations.
// It abstracts NVML initialization and device/system queries.
type nvmlHandler interface {
	Init() nvml.Return
	Shutdown() nvml.Return
	DeviceGetCount() (int, nvml.Return)
	DeviceGetHandleByIndex(i int) (NVMLDevice, nvml.Return)
	SystemGetDriverVersion() (string, nvml.Return)
	SystemGetConfComputeState() (nvml.ConfComputeSystemState, nvml.Return)
}

// defaultNVMLHandler is the default implementation of nvmlHandler,
// providing access to actual NVML library functions.
type defaultNVMLHandler struct {
}

// Init initializes the NVML library.
func (*defaultNVMLHandler) Init() nvml.Return {
	return nvml.Init()
}

// Shutdown shuts down the NVML library.
func (*defaultNVMLHandler) Shutdown() nvml.Return {
	return nvml.Shutdown()
}

// SystemGetConfComputeState retrieves the confidential compute system state from NVML.
func (*defaultNVMLHandler) SystemGetConfComputeState() (nvml.ConfComputeSystemState, nvml.Return) {
	computeState, ret := nvml.SystemGetConfComputeState()
	return computeState, ret
}

// DeviceGetCount returns the number of NVML devices present in the system.
func (*defaultNVMLHandler) DeviceGetCount() (int, nvml.Return) {
	return nvml.DeviceGetCount()
}

// DeviceGetHandleByIndex returns a handle to the NVML device at the specified index.
func (*defaultNVMLHandler) DeviceGetHandleByIndex(i int) (NVMLDevice, nvml.Return) {
	d, ret := nvml.DeviceGetHandleByIndex(i)
	if ret != nvml.SUCCESS {
		return nil, ret
	}
	return &defaultNVMLDevice{
		device: d,
	}, nvml.SUCCESS
}

// SystemGetDriverVersion returns the version of the NVIDIA driver.
func (*defaultNVMLHandler) SystemGetDriverVersion() (string, nvml.Return) {
	return nvml.SystemGetDriverVersion()
}

// NVMLDevice defines the interface for NVML device operations.
type NVMLDevice interface {
	GetDevice() nvml.Device
	GetUUID() (string, nvml.Return)
	GetBoardID() (uint32, nvml.Return)
	GetArchitecture() (nvml.DeviceArchitecture, nvml.Return)
	GetVbiosVersion() (string, nvml.Return)
	GetConfComputeGpuAttestationReport(nonce []byte) (nvml.ConfComputeGpuAttestationReport, nvml.Return)
	GetConfComputeGpuCertificate() (nvml.ConfComputeGpuCertificate, nvml.Return)
}

// defaultNVMLDevice implements NVMLDevice for actual NVML devices.
type defaultNVMLDevice struct {
	device nvml.Device
}

// GetDevice returns the underlying nvml.Device.
func (n *defaultNVMLDevice) GetDevice() nvml.Device {
	return n.device
}

// GetUUID returns the UUID of the NVML device.
func (n *defaultNVMLDevice) GetUUID() (string, nvml.Return) {
	return n.device.GetUUID()
}

// GetBoardID returns the board ID of the NVML device.
func (n *defaultNVMLDevice) GetBoardID() (uint32, nvml.Return) {
	return nvml.DeviceGetBoardId(n.device)
}

// GetArchitecture returns the architecture of the NVML device.
func (n *defaultNVMLDevice) GetArchitecture() (nvml.DeviceArchitecture, nvml.Return) {
	return nvml.DeviceGetArchitecture(n.device)
}

// GetVbiosVersion returns the VBIOS version of the NVML device.
func (n *defaultNVMLDevice) GetVbiosVersion() (string, nvml.Return) {
	return nvml.DeviceGetVbiosVersion(n.device)
}

// GetConfComputeGpuAttestationReport retrieves the confidential compute GPU attestation report.
func (n *defaultNVMLDevice) GetConfComputeGpuAttestationReport(nonce []byte) (nvml.ConfComputeGpuAttestationReport, nvml.Return) {
	return nvml.DeviceGetConfComputeGpuAttestationReportWithNonce(n.device, nonce)
}

// GetConfComputeGpuCertificate retrieves the confidential compute GPU certificate.
func (n *defaultNVMLDevice) GetConfComputeGpuCertificate() (nvml.ConfComputeGpuCertificate, nvml.Return) {
	return nvml.DeviceGetConfComputeGpuCertificate(n.device)
}
