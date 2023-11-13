---
last_updated: 16 February 2024
---

# Intel® Trust Authority Go TDX Adapter
Go module for collecting TDX Quote from GCP TDX enabled platform.

This TDX Adadpter is specifically built to work with Google Cloud TDX stack. It refers Google's [go-tdx-guest](https://github.com/google/go-tdx-guest/tree/main) for Quote generation.

## Requirements

- Use **Go 1.19 or newer**. See [https://go.dev/doc/install](https://go.dev/doc/install) for installation of Go.
- Intel® Software Guard Extensions Data Center Attestation Primitives (Intel® SGX DCAP) is required on the attesting TEE for quote generation.  For Intel SGX DCAP installation, see [https://github.com/intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives).

## Unit Tests

To run the tests, run `cd go-tdx && go test ./... --tags=test`. See the example test in `go-tdx/crypto_test.go` for an example of a test.

## Usage

### To Create a new Intel TDX adapter

**NewEvidenceAdapter()** and then use the adapter to collect a quote from a TD. NewEvidenceAdapter() accepts two optional arguments: **tdHeldData**, and **EventLogParser**. **tdHeldData**  is binary data provided by the client. tdHeldData, if provided, is output to the **attester_held_data** claim in the attestation token. **EventLogParser** allows you to provide a log parser for ACPI or UEFI logs, if your Intel TDX-enabled platform exposes the logs. 

**CollectEvidence()** requires a **nonce** argument. A SHA512 hash is calculated for the nonce and tdHeldData (if any) and saved in the TD quote REPORTDATA field. If successful, CollectEvidence() returns a TD quote that's formatted for attestation by Intel Trust Authority.

```go
import "github.com/intel/trustauthority-client/go-tdx"

adapter, err := tdx.NewEvidenceAdapter(tdHeldData, nil)
if err != nil {
    return err
}

evidence, err := adapter.CollectEvidence(nonce)
if err != nil {
    return err
}
```

### To collect event log from TD

Note that the TD must have an exposed ACPI table for event log collection.

```go
evLogParser := tdx.NewEventLogParser()
eventLog, err := evLogParser.GetEventLogs()
if err != nil {
    return err
}
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
