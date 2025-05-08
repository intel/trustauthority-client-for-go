# Intel® Trust Authority Client Go Connector

<p style="font-size: 0.875em;">· 10/18/2024 ·</p>

The [Intel® Trust Authority](https://www.intel.com/content/www/us/en/security/trust-authority.html) **go-connector** module is the main component of the remote attestation client. The go-connector provides a set of Go modules for connecting to Intel Trust Authority services. The go-connector API is designed to be used by both attesters and relying parties, in either Passport or Background-check attestation mode. Go-connector relies on _TEE adapters_ to interact with the underlying host platform. 

There are two options for using **go-connector**: you can import the Go modules into your Go application, or you can execute the [attestation client CLI](https://docs.trustauthority.intel.com/main/articles/integrate-go-tdx-cli.html) from your application or workflow. The CLI is a wrapper around the go-connector that provides a command-line interface the core functionality of the go-connector, plus additional features exposed by TEE adapters.

**go-connector** requires configuration information to connect to the Intel Trust Authority service. The configuration information includes the URL of the Intel Trust Authority service for your region, the API key, TLS configuration, and optional connection retry parameters. For more information, see the [sample configuration code](https://docs.trustauthority.intel.com/main/articles/integrate-go-client.html#go-connector-api).

For more information about **go-connector** and related topics, see the following resources:
- [Intel Trust Authority Go Connector Reference](https://docs.trustauthority.intel.com/main/articles/integrate-go-client.html) — Detailed documentation for the go-connector API. 
- [Intel Trust Authority Attestation Client CLI](https://docs.trustauthority.intel.com/main/articles/integrate-go-tdx-cli.html) — Documentation for the attestation client CLI.
- [Intel Trust Authority Documentation](https://docs.trustauthority.intel.com/main/) —The primary documentation for Intel Trust Authority.
- [Intel Trust Authority Client README](../README.md) — The main README for this branch.


## Download **go-connector**

Download the latest version of the module with the following command.

```sh
go get github.com/intel/trustauthority-client/go-connector
```

## Go Requirement

Use **Go 1.23 or newer**. See https://go.dev/doc/install for installation of Go.

## Unit Tests

To run the tests, run `cd go-connector && go test ./...`. See the example test in `go-connector/token_test.go` for an example of a test.

## Usage

For usage information, see the [Intel Trust Authority Go Connector Reference](https://docs.trustauthority.intel.com/main/articles/integrate-go-client.html).

## Code of Conduct and Contributing

See the [CONTRIBUTING](../CONTRIBUTING.md) file for information on how to contribute to this project. The project follows the [ Code of Conduct](../CODE_OF_CONDUCT.md).

## License

This library is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.

