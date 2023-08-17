# Intel Project Amber Go Client Library - API V1
This is the beta version of Go Library for integrating with Intel Project Amber V1 API.

## Installation

Install the latest version of the library with the following commands:

```sh
go get github.com/intel/amber-client/go-client
```

## Go Requirement

Use <b>go1.17 or newer</b>.

## Unit Tests

To run the tests, run `cd go-client && go test ./...`

See the example test in `go-client/token_test.go` for an example of a test.

## Usage

Create a new Project Amber client, then use the exposed services to
access different parts of the Project Amber API.

```go
import amberclient "github.com/intel/amber-client/go-client"

cfg := amberclient.Config{
        // Replace AMBER_URL with real Amber URL
        BaseUrl: "AMBER_URL",
        // Replace AMBER_API_URL with real Amber Attestation API URL
        ApiUrl: "AMBER_API_URL",
        // Provide TLS config
        TlsCfg: &tls.Config{},
        // Replace AMBER_API_KEY with your real key
        ApiKey: "AMBER_API_KEY",

        RClient: &RetryConfig{},
}

// RetryConfig a retryable client configuration for automatic retries to tolerate minor outages.
rCfg := amberclient.RetryConfig{
        // Minimum time to wait, default is 2s
        RetryWaitMin:
        // Maximum time to wait, default is 10s
        RetryWaitMax: 
        // Maximum number of retries, default is 2
        RetryMax:    
        // CheckRetry specifies the policy for handling retries, and is called
        // after each request. Default retries when http status code is one amone 500, 503 and 504
        // and when there is client timeout
        CheckForRetry: 
        // Backoff specifies the policy for how long to wait between retries, default is DefaultBackoff, which 
        // provides a default callback for Client.Backoff which will perform exponential backoff based on the attempt 
        // number and limited by the provided minimum and maximum durations.
        BackOff:       
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

### To download Amber token signing certificates

```go
jwks, err := client.GetAmberCertificates()
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To collect Amber signed token with Adapter
To create adapter refer [go-sgx](./go-sgx/README.md) or [go-tdx](./go-tdx/README.md):

```go
token, err := client.CollectToken(adapter, policyIds)
if err != nil {
    return err
}
```

## License

This library is distributed under the BSD-style license found in the [LICENSE](./LICENSE)
file.
