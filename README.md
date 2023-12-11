# Intel® Trust Authority Client
Intel Trust Authority Client provides a set of Go modules and command line interfaces for attesting different TEEs with Intel Trust Authority.
It is flexible enough that either the users can import the Go modules within their application or they can directly invoke the CLIs from their application.  
**Note: if you're evaluating Azure TDX public preview environment, please checkout this branch instead of main: [azure-tdx-preview](https://github.com/intel/trustauthority-client-for-go/tree/azure-tdx-preview)**

## Modes of Integration

The Client provides following modules which can be imported by an application to attest the SGX and TDX TEEs with Intel Trust Authority:
1. [go-connector](./go-connector): Provides an HTTPClient interface to communicate with Intel Trust Authority via REST APIs.
2. [go-sgx](./go-sgx): Implements an EvidenceAdapter interface to collect the SGX quote.
3. [go-tdx](./go-tdx): Implements an EvidenceAdapter interface to collect the TDX quote.

The Client additionally provides following command line interfaces which can be directly invoked by an application to attest the TDX TEE with Intel Trust Authority:
1. [tdx-cli](./tdx-cli): Provides a command line interface to attest the TDX TEE(TD) with Intel Trust Authority.

## Go Requirement

Use <b>go1.19 or newer</b>. Follow https://go.dev/doc/install for installation of Go.

## License

This library is distributed under the BSD-style license found in the [LICENSE](./LICENSE)
file.
