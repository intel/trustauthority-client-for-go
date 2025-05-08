# Intel® Trust Authority Go SGX Adapter

<p style="font-size: 0.875em;">· 10/10/2024 ·</p>

The **go-sgx** adapter enables a confidential computing client running in an Intel® Software Guard Extensions (Intel® SGX) enclave to collect a quote for attestation by Intel Trust Authority. The **go-sgx** adapter is used with the [**go-connector**](../go-connector/) to request an attestation token. For more information about **go-sgx**, see [go-sgx APIs](https://docs.trustauthority.intel.com/main/articles/integrate-go-client.html#go-sgx-apis) in the Intel Trust Authority documentation.

## Requirements

- Use **Go 1.23 or newer**. See [https://go.dev/doc/install](https://go.dev/doc/install) for installation of Go.
- Intel® Software Guard Extensions Data Center Attestation Primitives (Intel® SGX DCAP) is required on the attesting TEE for quote generation.  For Intel SGX DCAP installation, see [https://github.com/intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives).

## Usage

Create a new **go-sgx** adapter, then use the adapter to collect quote from an Intel SGX-enabled platform. The Intel SGX enclave must expose a method for creating an enclave report and must use a SHA256 hash value as REPORTDATA.

```go
import "github.com/intel/trustauthority-client/go-sgx"

adapter, err := sgx.NewEvidenceAdapter(enclaveId, enclaveHeldData, unsafe.Pointer(C.enclave_create_report))
if err != nil {
    return err
}

evidence, err := adapter.CollectEvidence(nonce)
if err != nil {
    return err
}
```

## Code of Conduct and Contributing

See the [CONTRIBUTING](../CONTRIBUTING.md) file for information on how to contribute to this project. The project follows the [ Code of Conduct](../CODE_OF_CONDUCT.md).

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
