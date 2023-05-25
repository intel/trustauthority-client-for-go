# Intel Project Amber Go TDX Adapter
This is the beta version of Go TDX Azure Adapter for collecting Quote from TDX enabled platform.

## Go Requirement

Use <b>go1.17 or newer</b>.

## Usage

Create a new Go TDX adapter, then use the adapter to
collect quote from TDX enabled platform.

```go
import "github.com/intel/amber-client/go-tdx"

evLogParser := tdx.NewEventLogParser()
adapter, err := tdx.NewAzureAdapter(tdHeldData, evLogParser)
if err != nil {
    return err
}

evidence, err := adapter.CollectEvidence(nonce)
if err != nil {
    return err
}
```

### To decrypt an encrypted blob

```go
em := &tdx.EncryptionMetadata{
	PrivateKeyLocation: privateKeyPath,
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
