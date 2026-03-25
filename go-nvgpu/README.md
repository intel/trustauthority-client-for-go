# Intel® Trust Authority Go Adapter for NVIDIA GPU

<p style="font-size: 0.875em;">· 03/23/2026 ·</p>

The **go-nvgpu** adapter enables a client to collect remote attestation evidence from NVIDIA® confidential computing GPUs for attestation by Intel Trust Authority. The **go-nvgpu** adapter is used with the [**go-connector**](../go-connector/) to request an attestation token.

Supported GPU architectures:
- **NVIDIA Hopper** (H100/H200 series)
- **NVIDIA Blackwell** (B100/B200 series)

The adapter uses the [NVIDIA Management Library (NVML)](https://github.com/NVIDIA/go-nvml) to communicate with the GPU, collects a confidential-computing attestation report and certificate chain from each supported device, verifies the certificate chain, and returns the evidence as a `GPUEvidence` structure ready for submission to Intel Trust Authority.

## Requirements

- Use **Go 1.25 or newer**. See [https://go.dev/doc/install](https://go.dev/doc/install) for installation of Go.
- An NVIDIA Hopper or Blackwell GPU with Confidential Computing (CC) mode enabled.
- The NVIDIA driver and NVML library must be installed and accessible on the host.
- The `github.com/NVIDIA/go-nvml` package (included in the module's `go.mod`).

## Usage

### Basic usage

Create a new **go-nvgpu** composite evidence adapter and use it to collect GPU attestation evidence. The adapter obtains a remote attestation report and verifies the certificate chain for each supported GPU on the system.

```go
import "github.com/intel/trustauthority-client/go-nvgpu"

adapter := nvgpu.NewCompositeEvidenceAdapter()

evidence, err := adapter.GetEvidence(verifierNonce, nil)
if err != nil {
    return err
}
```

### With NRAS API key

If your deployment requires authentication with the NVIDIA Remote Attestation Service (NRAS), provide the API key via the `WithNrasApiKey` option:

```go
import "github.com/intel/trustauthority-client/go-nvgpu"

adapter := nvgpu.NewCompositeEvidenceAdapter(
    nvgpu.WithNrasApiKey("your-nras-api-key"),
)

evidence, err := adapter.GetEvidence(verifierNonce, nil)
if err != nil {
    return err
}
```

### With a custom GPUAttester

For testing or advanced use cases, you can inject a custom `GPUAttester` implementation using the `WithGpuAttester` option:

```go
import "github.com/intel/trustauthority-client/go-nvgpu"

adapter := nvgpu.NewCompositeEvidenceAdapter(
    nvgpu.WithGpuAttester(myCustomAttester),
)

evidence, err := adapter.GetEvidence(verifierNonce, nil)
if err != nil {
    return err
}
```

## Evidence structure

`GetEvidence` returns a `*GPUEvidence` value with the following fields:

| Field | Type | Description |
| --- | --- | --- |
| `gpu_nonce` | `string` | Hex-encoded nonce used for attestation (SHA-256 of verifier nonce/random nonce). |
| `verifier_nonce` | `*connector.VerifierNonce` | The verifier nonce, if provided. |
| `arch` | `string` | GPU architecture of the first attested device (e.g. `"hopper"`, `"blackwell"`). |
| `evidence_list` | `[]Evidence` | List of per-GPU evidence entries. |
| `nras_apikey` | `string` | NRAS API key, if configured. |

Each `Evidence` entry in `evidence_list` contains:

| Field | Type | Description |
| --- | --- | --- |
| `evidence` | `string` | Base64-encoded GPU attestation report. |
| `certificate` | `string` | Base64-encoded, verified certificate chain. |
| `firmware_version` | `string` | GPU firmware version (if available). |

## Evidence identifier

The adapter's evidence identifier (returned by `GetEvidenceIdentifier()`) is `"nvgpu"`.

## Unit Tests

To run the unit tests:

```sh
cd go-nvgpu && go test ./...
```

## Code of Conduct and Contributing

See the [CONTRIBUTING](../CONTRIBUTING.md) file for information on how to contribute to this project. The project follows the [Code of Conduct](../CODE_OF_CONDUCT.md).

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE) file.
