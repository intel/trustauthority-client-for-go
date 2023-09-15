# Intel® Trust Authority Connector
Go module for communicating with Intel Trust Authority via REST APIs.

## Download

Download the latest version of the module with the following command:

```sh
go get github.com/intel/trustauthority-client/go-connector
```

## Go Requirement

Use <b>go1.19 or newer</b>. Follow https://go.dev/doc/install for installation of Go.

## Unit Tests

To run the tests, run `cd go-connector && go test ./...`

See the example test in `go-connector/token_test.go` for an example of a test.

## Usage

Create a new Connector instance, then use the exposed interfaces to
access different parts of the Intel Trust Authority API.

```go
import "github.com/intel/trustauthority-client/go-connector"

cfg := connector.Config{
        // Replace TRUSTAUTHORITY_URL with real Intel Trust Authority URL
        BaseUrl: "TRUSTAUTHORITY_URL",
        // Replace TRUSTAUTHORITY_API_URL with real Intel Trust Authority API URL
        ApiUrl: "TRUSTAUTHORITY_API_URL",
        // Provide TLS config
        TlsCfg: &tls.Config{},
        // Replace TRUSTAUTHORITY_API_KEY with real API key
        ApiKey: "TRUSTAUTHORITY_API_KEY",
        // Provide Retry config
        RClient: &connector.RetryConfig{},
}

retryCfg := connector.RetryConfig{
        // Minimum time to wait between retries, default is 2s
        RetryWaitMin:
        // Maximum time to wait between retries, default is 10s
        RetryWaitMax:
        // Maximum number of retries, default is 2
        RetryMax:
        // CheckRetry specifies the policy for handling retries, and is called
        // after each request. Default retries when http status code is one among 500, 503 and 504
        // and when there is client timeout or if a service is unavailable
        CheckRetry:
        // Backoff specifies the policy for how long to wait between retries, default is DefaultBackoff, which 
        // provides a default callback for Backoff which will perform exponential backoff based on the attempt
        // number and limited by the provided minimum and maximum durations.
        BackOff:
}

connector, err := connector.New(&cfg)
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To get Intel Trust Authority signed nonce

```go
req := connector.GetNonceArgs{
    RequestId: reqId,
}
resp, err := connector.GetNonce(req)
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To get Intel Trust Authority signed token with Nonce and Evidence

```go
req := connector.GetTokenArgs{
    Nonce:     nonce,
    Evidence:  evidence,
    PolicyIds: policyIds,
    RequestId: reqId,
}
resp, err := connector.GetToken(req)
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To verify Intel Trust Authority signed token

```go
parsedToken, err := connector.VerifyToken(string(token))
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To download Intel Trust Authority token signing certificates

```go
jwks, err := connector.GetTokenSigningCertificates()
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To attest TEE with Intel Trust Authority using TEE Adapter
To create adapter refer [go-sgx](../go-sgx/README.md) or [go-tdx](../go-tdx/README.md):

```go
req := connector.AttestArgs{
    Adapter:   adapter,
    PolicyIds: policyIds,
    RequestId: reqId,
}
resp, err := connector.Attest(req)
if err != nil {
    return err
}
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
