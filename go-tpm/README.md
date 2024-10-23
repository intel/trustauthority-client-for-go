# Intel® Trust Authority TPM Adapter for Go

<p style="font-size: 0.875em;">· 10/23/2024 ·</p>

This  version of the TPM (Trusted Platform Module) adapter provides a set of APIs for interacting with TPMs. The adapter can be used to read and write NV indexes, read PCRs, and get quotes. In this release the adapter supports Microsoft Azure\* confidential virtual machines with Intel® Trust Domain Extensions (Intel® TDX) and vTPM 2.0. 

The TPM adapter is used to get evidence from the vTPM. The evidence is endorsed by the Azure-provided attestation key (AK), which is contained in the Intel TDX quote's runtime data. The Azure CVM with Intel TDX adapter (**go-aztdx**) is used to get evidence from the Intel TDX trust domain TEE. The evidence from the vTPM and the Intel TDX is combined and sent to Intel Trust Authority for composite attestation. If attestation is successful, Intel Trust Authority issues a JWT (JSON Web Token) that can be used to verify the integrity of the vTPM and the Intel TDX trust domain.

For detailed documentation of the TPM adapter, see the [TPM API Reference](https://docs.trustauthority.intel.com/main/articles/integrate-go-tpm.html) in the Intel Trust Authority documentation.

## Prerequisites

- Go 1.22 or later

## Usage

You'll need to import the following packages into your project to attest an Azure confidential VM with Intel TDX and vTPM:

```go
import(
	"github.com/intel/trustauthority-client/aztdx"
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/tpm"
)
```

## Code of Conduct and Contributing

See the [CONTRIBUTING](../CONTRIBUTING.md) file for information on how to contribute to this project. The project follows the [ Code of Conduct](../CODE_OF_CONDUCT.md).

## License

This library is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.

<br><br>
---
**\*** Other names and brands may be claimed as the property of others.