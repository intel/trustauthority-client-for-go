---
last_updated: 16 February 2024
---

# Intel® Trust Authority Go TDX Adapter
Go module for collecting TDX Quote from MSFT Azure TDX enabled platform.
This module is specifically built to work with Azure TDX stack only.

The **go-tdx** adapter enables a confidential computing client running in an Intel® Trust Domain Extensions (Intel® TDX) trust domain (TD) to collect a quote for attestation by Intel Trust Authority. The go-tdx adapter is used with the [**go-connector**](../go-connector/) to request an attestation token. 

## Requirements

- Use **Go 1.19 or newer**. See [https://go.dev/doc/install](https://go.dev/doc/install) for installation of Go.

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

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
