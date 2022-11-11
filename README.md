# Intel Project Amber Go Client Library - API V1
This is the beta version of Go Library for integrating with Intel Project Amber V1 API.

You can view Intel Project Amber API docs here: [https://intel.github.io/amber-docs/rest/overview/](https://intel.github.io/amber-docs/rest/overview/)

## Installation

Install the latest version of the library with the following commands:

```sh
go get github.com/intel/amber-client/go-client
```

## Go Requirement

Use <b>go1.17 or newer</b>.

## Usage

Create a new Project Amber client, then use the exposed services to
access different parts of the Project Amber API.

```go
import amberclient "github.com/intel/amber-client/go-client"

cfg := amberclient.Config{
        // Replace AMBER_API_URL with real Amber URL
        Url: "AMBER_API_URL",
        // Provide TLS config
        TlsCfg: &tls.Config{},
        // Replace AMBER_API_KEY with your real key
        ApiKey: "AMBER_API_KEY",
}

client, err := amberclient.New(&cfg)
```

### To get a Amber signed nonce

```go
nonce, err := client.GetNonce()
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To get a Amber signed token with Nonce and Evidence

```go
token, err := client.GetToken(nonce, policyIds, evidence)
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To verify a Amber signed token

```go
parsedToken, err := client.VerifyToken(string(token))
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To collect Amber signed token with Adapter
To create adapter refer [go-sgx](./go-sgx/README.md):

```go
token, err := client.CollectToken(adapter, policyIds)
if err != nil {
    return err
}
```

## License

This library is distributed under the BSD-style license found in the [LICENSE](./LICENSE)
file.
