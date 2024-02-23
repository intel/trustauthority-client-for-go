---
last_updated: 30 January 2024
---

# Intel® Trust Authority Go SGX Adapter

The **go-sgx** adapter enables a confidential computing client running in an Intel® Software Guard Extensions (Intel® SGX) enclave to collect a quote for attestation by Intel Trust Authority. The go-sgx adapter is used with the [**go-connector**](../go-connector/) to request an attestation token. 

## Requirements

- Use **Go 1.19 or newer**. See [https://go.dev/doc/install](https://go.dev/doc/install) for installation of Go.
- Intel® Software Guard Extensions Data Center Attestation Primitives (Intel® SGX DCAP) is required on the attesting TEE for quote generation.  For Intel SGX DCAP installation, see [https://github.com/intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives).

## Usage

Create a new Go SGX adapter, then use the adapter to collect quote from SGX enabled platform. The Intel SGX enclave must expose a method for creating an enclave report and must use a SHA256 hash value as REPORTDATA.

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

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
