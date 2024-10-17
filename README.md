---
last_updated: 8 May 2024
---

# Intel® Trust Authority Client

[Intel® Trust Authority](https://www.intel.com/content/www/us/en/security/trust-authority.html) Client for Go ("the Client") provides a set of Go modules and command line interfaces (CLI) for attesting different TEEs with Intel Trust Authority. The Client can be used by both attesters and relying parties, in either Passport or Background-check attestation mode. You can import the Go modules into your application, or you can directly invoke the CLI for Intel® TDX attestation from your application or workflow.

Supported TEEs include [Intel® Software Guard Extensions](https://www.intel.com/content/www/us/en/products/docs/accelerator-engines/software-guard-extensions.html) (Intel® SGX) and [Intel® Trust Domain Extensions](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) (Intel® TDX), [Azure confidential VMs with Intel TDX](https://azure.microsoft.com/en-us/updates/confidential-vms-with-intel-tdx-dcesv5-ecesv5-public-preview/) (Preview), and Google Cloud Platform (GCP) [Confidential VMs on Intel CPUs with Intel TDX](https://cloud.google.com/blog/products/identity-security/confidential-vms-on-intel-cpus-your-datas-new-intelligent-defense) (Preview). Eventually, other platforms may be added. 

For more information about the Client for Go and CLI for Intel TDX, see [Client integration reference](https://docs.trustauthority.intel.com/main/articles/integrate-overview.html) in the Intel Trust Authority documentation.

## Methods of Integration

The Client provides the following modules that can be imported by an application to attest Intel® SGX and Intel® TDX TEEs by using Intel Trust Authority. 

1. [go-connector](./go-connector): Provides an HTTPClient interface to communicate with Intel Trust Authority via REST APIs for remote attestations services, and functions to verify an attestation token and download the JWKS of token signing certificates. The Connector can be used by attesters or relying parties.
1. [go-sgx](./go-sgx): Implements an adapter interface to Intel® SGX DCAP to collect evidence from an Intel SGX enclave for attestation by Intel Trust Authority. 
1. [go-tdx](./go-tdx): Implements an adapter interface to collect evidence from an Intel TDX trust domain (TD) for attestation by Intel Trust Authority. The go-tdx adapter also implements utility functions to decrypt a blob or create a new RSA key pair. 

Intel Trust Authority CLI for Intel TDX [tdx-cli](./tdx-cli) provides a CLI to attest an Intel TDX TD with Intel Trust Authority. tdx-cli requires go-connector and go-tdx. See the [README](./tdx-cli/README.md) for details.

## Go Requirement

Requires **Go 1.22 or newer**. See https://go.dev/doc/install for installation of Go.

## License

This library is distributed under the BSD-style license found in the [LICENSE](./LICENSE)
file.
