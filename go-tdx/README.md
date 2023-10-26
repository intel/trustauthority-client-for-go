# Intel® Trust Authority Go TDX Adapter
Go module for collecting TDX Quote from GCP TDX enabled platform.

This TDX Adadpter is specifically built to work with Google Cloud TDX stack. It refers Google's [go-tdx-guest](https://github.com/google/go-tdx-guest/tree/main) for Quote generation.

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

### To generate RSA keypair

```go
km := &tdx.KeyMetadata{
	KeyLength: 3072,
}
privateKeyPem, publicKeyPem, err := tdx.GenerateKeyPair(km)
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To decrypt an encrypted blob

```go
em := &tdx.EncryptionMetadata{
	PrivateKeyLocation: privateKeyPath,
	HashAlgorithm:      "SHA256",
}
decryptedData, err := tdx.Decrypt(encryptedData, em)
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To collect event log from TD
Note that the TD should have exposed ACPI table for eventlog collection.

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
