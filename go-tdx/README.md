---
last_updated: 16 February 2024
---

# Intel® Trust Authority Go TDX Adapter

The **go-tdx** adapter enables a confidential computing client running in an Intel® Trust Domain Extensions (Intel® TDX) trust domain (TD) to collect a quote for attestation by Intel Trust Authority. The go-tdx adapter is used with the [**go-connector**](../go-connector/) to request an attestation token. 

## Requirements

- Use **Go 1.22 or newer**. See [https://go.dev/doc/install](https://go.dev/doc/install) for installation of Go.
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

### To generate an RSA key pair

**GenerateKeyPair()** takes a required **KeyMetadata** argument that specifies the length in bits for the key. If successful, it returns a public and private key.

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

**Decrypt()** accepts two arguments, **encryptedData** and **EncryptionMetadata**, and returns decrypted binary data. The HashAlgorithm must be one of [SHA256 | SHA384 | SHA512].

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
