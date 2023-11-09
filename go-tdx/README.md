# Intel® Trust Authority Go TDX Adapter
Go module for collecting TDX Quote from MSFT Azure TDX enabled platform.
This module is specifically built to work with Azure TDX stack only.

## Go Requirement

Use <b>go1.19 or newer</b>. Follow https://go.dev/doc/install for installation of Go.

## Unit Tests

To run the tests, run `cd go-tdx && go test ./... --tags=test`

See the example test in `go-tdx/crypto_test.go` for an example of a test.

## Usage

Create a new TDX adapter, then use the adapter to collect quote from TDX enabled platform.
Optionally collect the eventlog as well for a TD by passing an eventlog parser in second argument.

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
