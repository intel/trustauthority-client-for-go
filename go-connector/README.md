---
last_updated: 30 January 2024
---

# Intel® Trust Authority Connector

The [Intel® Trust Authority](https://www.intel.com/content/www/us/en/security/trust-authority.html) **go-connector** module is the main component of the integration client. The go-connector provides attestation and verification functions, and it can be used by an attester in a supported TEE, or by a relying party. A relying party can run the go-connector as a standalone module; it does not require Intel® SGX DCAP or a TEE adapter. A confidential computing workload (the attester) running in a supported TEE requires the go-connector and a TEE adapter module to collect evidence (a quote) from the TEE. 

For more information about the Client for Go and CLI for Intel TDX, see [Client integration reference](https://docs.trustauthority.intel.com/main/articles/integrate-overview.html) in the Intel Trust Authority documentation.

## Download

Download the latest version of the module with the following command.

```sh
go get github.com/intel/trustauthority-client/go-connector
```

## Go Requirement

Use **Go 1.19 or newer**. See https://go.dev/doc/install for installation of Go.

## Unit Tests

To run the tests, run `cd go-connector && go test ./...`

See the example test in `go-connector/token_test.go` for an example of a test.

## Usage

Create a new Connector instance, and then use the exposed interfaces to
access different parts of the Intel Trust Authority API.

```go
import "github.com/intel/trustauthority-client/go-connector"

cfg := connector.Config{
        // Intel Trust Authority base URL
        BaseUrl: "https://portal.trustauthority.intel.com",
        // Intel Trust Authority API URL
        ApiUrl: "https://api.trustauthority.intel.com",
        // Provide TLS config
        TlsCfg: &tls.Config{},
        // Replace TRUSTAUTHORITY_API_KEY with an **attestation** API key
        ApiKey: "TRUSTAUTHORITY_API_KEY",
        // Provide Retry config 
        RClient: &connector.RetryConfig{},
}

retryCfg := connector.RetryConfig{
        // Minimum time to wait between retries, default is 2s.
        RetryWaitMin:
        // Maximum time to wait between retries, default is 10s.
        RetryWaitMax:
        // Maximum number of retries, default is 2.
        RetryMax:
        // CheckRetry specifies the policy for handling retries, and is called
        // after each request. Default retries when http status code is one of 500, 503, or 504,
        // and when there is a client timeout or if a service is unavailable.
        CheckRetry:
        // Backoff specifies the policy for how long to wait between retries, default is DefaultBackoff, which 
        // provides a default callback for Backoff that will perform an exponential backoff based on the attempt
        // number and limited by the provided minimum and maximum durations.
        BackOff:
}

connector, err := connector.New(&cfg)
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To get an Intel Trust Authority signed nonce

**GetNonce()** accepts an optional [RequestID](https://docs.trustauthority.intel.com/main/articles/glossary.html#request-id) that you can use to track API requests. If successful, GetNonce() returns the nonce and HTTP response headers, or an error if unsuccessful. 

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

### To get Intel Trust Authority attestation token

There are two methods for requesting an attestation token: **Attest()** and **GetToken()**. Attest() is the simplest method to implement for Passport attestation. GetToken() supports the Background-check attestation model. The following code fragment assumes that you have previously obtained a nonce and a quote. 

If successful, GetToken() returns an Intel Trust Authority attestation token (JWT) and the HTTP response headers, or an error if unsuccessful. 

```go
req := connector.GetTokenArgs{
    Nonce:     nonce,
    Evidence:  evidence,
    PolicyIds: policyIds,
    RequestId: reqId,
    TokenSigningAlg: alg,
}
resp, err := connector.GetToken(req)
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To verify an attestation token

**VerifyToken()** takes an attestation token as input, and then checks the token format and verifies that it was signed with a genuine Intel Trust Authority certificate, and that the public key can be extracted from the certificate. VerifyToken() does not validate claims in the JWT body. VerifyToken() returns a parsed token in JWT format if successful, or an error if unsuccessful. 

```go
parsedToken, err := connector.VerifyToken(string(token))
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To download Intel Trust Authority token signing certificates

**GetTokenSigningCertificates()** gets the JWKS of certificates used by Intel Trust Authority to sign attestation tokens. To get the signing certificate for a given token, search the JWKS for the ID contained in the attestation token's **kid** claim.

```go
jwks, err := connector.GetTokenSigningCertificates()
if err != nil {
    fmt.Printf("Something bad happened: %s\n\n", err)
    return err
}
```

### To attest a TEE using Attest()

**Attest()** provides an all-in-one method for getting a nonce, collecting a quote from a TEE, and then requesting a attestation token from Intel Trust Authority. You need to create a Connector and a TEE adapter before calling Attest(). The sample above shows how to create a Connector. 

For more information about TEE adapters, see [go-sgx](../go-sgx/README.md) or [go-tdx](../go-tdx/README.md).

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
