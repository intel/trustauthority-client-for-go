---
last_updated: 10 July 2024
---

# Intel® Trust Authority Go SEVSNP Adapter

The **go-sevsnp** adapter enables a confidential computing client running in a SEVSNP VM to collect a SEVSNP report for attestation by Intel Trust Authority. The go-sevsnp adapter is used with the [**go-connector**](../go-connector/) to request an attestation token. 

The Intel Trust Authority Go SEVSNP Adapter is in preview, additional changes and improvements may be applied in future releases.

## Requirements

- Use **Go 1.22 or newer**. See [https://go.dev/doc/install](https://go.dev/doc/install) for installation of Go.
- The SEV-SNP platform/VM must be enabled with the SEV-SNP feature.

## Usage

Create a new Go SEVSNP adapter, then use the adapter to collect SEVSNP report from the SEVSNP platform. 

```go
import "github.com/intel/trustauthority-client/sevsnp"

adapter, err := sevsnp.NewEvidenceAdapter(teeHeldData))
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
