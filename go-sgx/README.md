# Intel® Trust Authority Go SGX Adapter
Go module for collecting SGX Quote from SGX enabled platform.

This library leverages Intel SGX DCAP for Quote generation: [https://github.com/intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives)

## Go Requirement

Use <b>go1.19 or newer</b>. Follow https://go.dev/doc/install for installation of Go.

## Usage

Create a new Go SGX adapter, then use the adapter to collect quote from SGX enabled platform.
SGX enclave needs to expose a method for creating enclave report and must use SHA256 hash value as reportdata.

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
