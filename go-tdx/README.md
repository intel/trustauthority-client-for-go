# Intel® Trust Authority Go Adapter for Intel TDX

<p style="font-size: 0.875em;">· 10/21/2024 ·</p>

The **go-tdx** adapter enables a confidential computing client running in an Intel® Trust Domain Extensions (Intel® TDX) trust domain (TD) to collect a quote for attestation by Intel Trust Authority. The go-tdx adapter is used with the [**go-connector**](../go-connector/) to request an attestation token. 

The **go-tdx** adapter can be used with any Intel TDX-enabled platform that supports `configfs`, a RAM-based filesystem that provides a kernel-based mechanism for obtaining Intel TDX evidence for an attestation quote. A separate adapter is provided for Azure confidential VMs with Intel TDX, but the Azure adapter is also provided in this branch. 

## Requirements

- Use **Go 1.25 or newer**. See [https://go.dev/doc/install](https://go.dev/doc/install) for installation of Go.
- An Intel TDX-enabled Linux platform with Kernel 6.7 or newer. The platform must have the `configfs` filesystem mounted at `/sys/kernel/config` and the Intel TDX kernel module loaded. This platform uses the `tdx_adapter.go` file.
- Alternatively, a Microsoft Azure confidential VM with Intel TDX and vTPM. This platform requires `aztdx_adapter.go`.

## Unit Tests

To run the tests, run `cd go-tdx && go test ./... --tags=test`. See the example test in `go-tdx/crypto_test.go` for an example of a test.

## Usage

### To Create a new Intel TDX adapter

**NewCompositeEvidenceAdapter()** and then use the adapter to collect a quote from a TD. NewCompositeEvidenceAdapter() accepts two optional arguments: **tdHeldData**, and **EventLogParser**. **tdHeldData**  is binary data provided by the client. tdHeldData, if provided, is output to the **attester_held_data** claim in the attestation token. **EventLogParser** allows you to provide a log parser for ACPI or UEFI logs, if your Intel TDX-enabled platform exposes the logs. 

**CollectEvidence()** requires a **nonce** argument. A SHA512 hash is calculated for the nonce and tdHeldData (if any) and saved in the TD quote REPORTDATA field. If successful, CollectEvidence() returns a TD quote that's formatted for attestation by Intel Trust Authority.

```go
import "github.com/intel/trustauthority-client/go-tdx"

adapter, err := tdx.NewCompositeEvidenceAdapter(false)
if err != nil {
    return err
}

evidence, err := adapter.GetEvidence(nil,nil)
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

### To include the confidenctial event log (CCEL) from TD
Provide 'true' to the NewCompositeEventAdapter function (Note: that the TD must have an exposed ACPI table for event log collection).

```go
import "github.com/intel/trustauthority-client/go-tdx"

adapter, err := tdx.NewCompositeEvidenceAdapter(true)
if err != nil {
    return err
}

evidence, err := adapter.GetEvidence(nil,nil)
if err != nil {
    return err
}
```

### Code of Conduct and Contributing

See the [CONTRIBUTING](../CONTRIBUTING.md) file for information on how to contribute to this project. The project follows the [ Code of Conduct](../CODE_OF_CONDUCT.md).

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
