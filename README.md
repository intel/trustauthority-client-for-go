# Intel® Trust Authority Client for Go

<p style="font-size: 0.875em;">· 01/20/2025 ·</p>

[Intel® Trust Authority](https://www.intel.com/content/www/us/en/security/trust-authority.html) [Client for Go](https://docs.trustauthority.intel.com/main/articles/integrate-go-client.html) ("the client") provides a set of Go modules and a command line interface (CLI) for attesting different TEEs with Intel Trust Authority. The attestation client API and [attestation client CLI](https://docs.trustauthority.intel.com/main/articles/integrate-go-tdx-cli.html) can be used by both attesters and relying parties, in either Passport or Background-check attestation mode. 

> [!NOTE]
> This is the General Availability (GA) release code for the Intel TDX host , Azure CVM\* with Intel TDX+vTPM , and GCP CVM with Intel TDX adapters are now consolidated in the **main** branch in the [`go-tdx`](./go-tdx/) directory. 
<br> <p style="font-size: 0.875em;">**\*** CVM = Confidential Virtual Machine</p>

> [!NOTE]
> The following preview branches are deprecated in this release: **azure-tdx-preview**, **tpm-preview**, and **gcp-tdx-preview**. These branches will be removed in the next release.

## Supported TEEs and Platforms
The Intel Trust Authority Client for Go works with the following TEEs and platforms:

| TEE or Platform | Status | Repo Branch | Notes |
| --- | --- | --- | --- |
| Intel® Software Guard Extensions (Intel® SGX) | GA | [**main**](https://github.com/intel/trustauthority-client-for-go/tree/main/go-sgx) | Bare metal host/on-premises. |
| Intel® Trust Domain Extensions (Intel® TDX) | GA | [**main**](https://github.com/intel/trustauthority-client-for-go/tree/main/go-tdx) | Bare metal hosts & cloud VMs that support configfs, such as GCP. See the notes above this table. |
| Azure\* confidential VMs with Intel TDX | GA | [**main**](https://github.com/intel/trustauthority-client-for-go/tree/main/go-aztdx) | Moved from Preview to GA status. See notes.|
| Azure\* confidential VMs with Intel TDX and vTPM | GA | [**main**](https://github.com/intel/trustauthority-client-for-go/tree/go-tpm) | Moved from Preview to GA status. See notes.|
| Google Cloud Platform\* (GCP) confidential VMs on Intel CPUs with Intel TDX | GA | [**main**](https://github.com/intel/trustauthority-client-for-go/tree/main/go-tdx) | Moved from Preview to GA status. See notes. |
| AMD Secure Encrypted Virtualization - Secure Nested Paging\* (AMD SEV-SNP\*) | Preview | [**sevsnp-preview**](https://github.com/intel/trustauthority-client-for-go/tree/sevsnp-preview) | Pilot environment only |
| Physical TPM | GA | [**main**](https://github.com/intel/trustauthority-client-for-go/tree/main) | GA |

Platforms with status **GA** are available and supported in the US and EU production environments. **Preview** TEEs and platforms are in limited-access preview status in the pilot environments only. Details of implementation and usage may change before general availability. The corresponding Intel Trust Authority attestation services for preview features are not available in the production environment. Contact your Intel representative for more information about the pilot program.

You can use the clients to collect the reference values needed for attestation policies. For example, you can create a known-good state for your TEE, use the client CLI to collect evidence, and then use the collected evidence values to create an [attestation policy](https://docs.trustauthority.intel.com/main/articles/concept-policy-v2.html) for Intel Trust Authority. 

Client libraries require **Go 1.23 or newer**. See https://go.dev/doc/install for installation of Go.

## Repo Structure

The repository **main** branch contains the following principal directories:

- **go-connector**: Go modules for connecting to Intel Trust Authority services. This is the core library.
- **go-sgx**: Go modules for attesting an Intel SGX enclave. 
- **go-tdx**: Go modules for attesting Intel TDX trust domains.
- **tdx-cli**: Attestation client command line interface (CLI). 
- **go-tpm**: Go modules for attesting a TPM.
- **go-aztdx**: Go modules for attesting an Azure confidential VM with Intel TDX and vTPM.
- **release**: Scripts for installing the client CLI for different platforms. Usage is described in the README files for the platform.

Preview branches are added as needed for preview versions of new TEE or platform adapters and features. The preview branches are named for the TEE or platform they support. Preview branches are based on **main**, with modifications as required. The README files in each branch describe the prerequisites and installation for the platform. 

The primary documentation for all of the client adapters including preview versions is available in the Intel Trust Authority documentation [Client integration reference](https://docs.trustauthority.intel.com/main/articles/integrate-overview.html).

## Code of Conduct and Contributing

See the [CONTRIBUTING](./CONTRIBUTING.md) file for information on how to contribute to this project. The project follows the [ Code of Conduct](./CODE_OF_CONDUCT.md).

## License

This library is distributed under the BSD-style license found in the [LICENSE](./LICENSE)
file.

<br><br>
---
**\*** Other names and brands may be claimed as the property of others.

<!--- links --->
