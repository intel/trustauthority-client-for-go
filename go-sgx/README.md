# Trust Connector Go SGX Adapter
This is the beta version of Go SGX Adapter for collecting Quote from SGX enabled platform.

This library leverages Intel SGX DCAP for Quote generation: [https://github.com/intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives)

## Go Requirement

Use <b>go1.17 or newer</b>.

## Usage

Create a new Go SGX adapter, then use the adapter to
collect quote from SGX enabled platform.

```go
import "github.com/intel/trustconnector/go-sgx"

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

This library is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
