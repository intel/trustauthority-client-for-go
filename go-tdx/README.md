# Intel® Trust Authority Go TDX Adapter
This is the beta version of Go TDX Adapter for collecting Quote from TDX enabled platform.

This library leverages Intel SGX DCAP for Quote generation: [https://github.com/intel/SGXDataCenterAttestationPrimitives](https://github.com/intel/SGXDataCenterAttestationPrimitives)

## Go Requirement

Use <b>go1.19 or newer</b>. Follow https://go.dev/doc/install for installation of Go.

## Unit Tests

To run the tests, run `cd go-tdx && go test ./... --tags=test`

See the example test in `go-tdx/crypto_test.go` for an example of a test.

## Usage

Create a new Go TDX adapter, then use the adapter to
collect quote from TDX enabled platform.

```go
import "github.com/intel/trustauthority-client/go-tdx"

evLogParser := tdx.NewEventLogParser()
adapter, err := tdx.NewEvidenceAdapter(tdHeldData, evLogParser)
if err != nil {
    return err
}

evidence, err := adapter.CollectEvidence(nonce)
if err != nil {
    return err
}
```

### To generate a RSA keypair

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

```go
evLogParser := tdx.NewEventLogParser()
eventLog, err := evLogParser.GetEventLogs()
if err != nil {
    return err
}
```

## License

This library is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
