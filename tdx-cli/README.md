# Intel® Trust Authority Attestation Client CLI

Intel® Trust Authority Attestation Client CLI (`trustauthority-cli`) provides a command-line interface for attesting supported platforms. It can be used manually, from scripts, or from application code when importing the Intel Trust Authority client packages is not practical. The CLI collects evidence, requests attestation tokens, verifies tokens, and can collect reference measurements from a known-good environment for use in appraisal policies.

The CLI is built with Go and is available in the [Intel Trust Authority Client for Go](https://github.com/intel/trustauthority-client-for-go) repository.

## Supported attestation technologies

- Intel® Trust Domain Extensions (Intel TDX) on-premises hosts, with or without composite TPM attestation.
- Azure confidential VMs with Intel TDX. Azure CVM vTPM is supported for composite attestation.
- Google Cloud Platform (GCP) confidential VMs with Intel TDX. GCP CVMs use the same TDX adapter as on-premises hosts.
- NVIDIA H100 GPUs, including composite attestation with an Intel TDX-based CVM.

The user running the CLI must have read and write permissions for the device that generates the quote. The required device and event-log permissions are described below.

## Installation on Linux

### Prerequisites

- Ubuntu 22.04 LTS or newer, SUSE Linux Enterprise Server (SLES) 15.6 or newer, Red Hat Enterprise Linux (RHEL) 8.0 or newer.
- Go 1.26.6 or newer when building from source. See the [Go installation instructions](https://go.dev/doc/install).
- Azure requires a customized OS distribution for confidential VMs. Ubuntu 22.04 confidential VM images are supported.

### Simplified installation

The installation script detects the distribution, installs required dependencies, and downloads the appropriate CLI binary. Ubuntu, SUSE, and RHEL are supported.

```sh
curl -sL https://raw.githubusercontent.com/intel/trustauthority-client-for-go/main/release/install-tdx-cli.sh | sudo bash -
```

The binary is installed as `/usr/bin/trustauthority-cli`.

### Verify the signature of the installed binary

The installer places the signing certificate and signature at `/usr/bin/trustauthority-cli.cer` and `/usr/bin/trustauthority-cli.sig`.

1. Extract the public key from the certificate:

   ```sh
   openssl x509 -in /usr/bin/trustauthority-cli.cer -pubkey -noout > /tmp/public_key.pem
   ```

2. Create a SHA-512 hash of the binary:

   ```sh
   openssl dgst -out /tmp/binaryHashOutput -sha512 -binary /usr/bin/trustauthority-cli
   ```

3. Verify the signature:

   ```sh
   openssl pkeyutl -verify -pubin -inkey /tmp/public_key.pem \
     -sigfile /usr/bin/trustauthority-cli.sig \
     -in /tmp/binaryHashOutput -pkeyopt digest:sha512 \
     -pkeyopt rsa_padding_mode:pss
   ```

## Build from source

Install the required packages for your operating system:

```sh
# Ubuntu
sudo apt install build-essential

# SUSE Linux
sudo zypper install git make
```

Clone and build the CLI:

```sh
git clone https://github.com/intel/trustauthority-client-for-go
cd trustauthority-client-for-go/tdx-cli/
make cli
```

This creates a `trustauthority-cli` binary in `tdx-cli/`. The build uses CGO and produces a position-independent executable with the release hardening options configured in the Makefile.

Run unit tests with:

```sh
cd tdx-cli
make test-coverage
```

## Configuration

Commands read configuration from JSON. The `--config` (`-c`) option specifies the file. The file path is required by the `token`, `evidence`, `verify`, and `provision-ak` commands. Configuration parsing rejects unknown properties.

The portal and API URLs depend on the region:

| Region | Portal URL | API URL |
| --- | --- | --- |
| World/US | `https://portal.trustauthority.intel.com` | `https://api.trustauthority.intel.com` |
| EU | `https://portal.eu.trustauthority.intel.com` | `https://api.eu.trustauthority.intel.com` |

Intel Trust Authority is not currently available to customers residing in the People's Republic of China.

### Basic configuration

```json
{
  "trustauthority_url": "https://portal.trustauthority.intel.com",
  "trustauthority_api_url": "https://api.trustauthority.intel.com",
  "trustauthority_api_key": "<trustauthority attestation API key>"
}
```

`trustauthority_url` is required by `verify`. `trustauthority_api_url` and `trustauthority_api_key` are required when requesting a token or when collecting evidence with a verifier nonce.

### Azure CVM with vTPM configuration

Set `cloud_provider` to `azure` only for Microsoft Azure. For Azure CVM attestation, the vTPM owner password is empty and the Azure-provisioned attestation key is at handle `81000003`.

```json
{
  "cloud_provider": "azure",
  "trustauthority_url": "https://portal.trustauthority.intel.com",
  "trustauthority_api_url": "https://api.trustauthority.intel.com",
  "trustauthority_api_key": "<trustauthority attestation API key>",
  "tpm": {
    "owner_auth": "",
    "ak_handle": "81000003",
    "pcr_selections": "sha1:10+sha256:all"
  }
}
```

### TPM configuration

The `tpm` section is needed only when using TPM evidence or provisioning a physical TPM attestation key.

- `owner_auth` is the TPM owner password.
- `ak_handle` is the attestation key handle. For Azure CVMs it is hardcoded to `81000003`; physical TPMs may use a configured handle.
- `ek_handle` is used by `provision-ak` to create the endorsement key. If omitted, the TPM default is used.
- `pcr_selections` identifies PCR banks and indices. The default includes all 24 SHA-256 PCRs. To collect IMA logs and enable event replay, include SHA-1 PCR 10, for example `sha1:10+sha256:all`. The PCR bank syntax follows the [tpm2-tools PCR bank specifier](https://tpm2-tools.readthedocs.io/en/latest/man/common/pcr/).
- `ak_certificate` identifies the AK certificate. It is used with physical TPMs and can be a `file://` URI or an `nvram://` index. The certificate is generated by Intel Trust Authority and must be saved after running `provision-ak`.

Virtual TPMs cannot be provisioned with an AK. The `ak_certificate` property is valid only for physical TPMs.

### NVIDIA GPU configuration

For GPU evidence, optionally provide the NVIDIA Remote Attestation Service API key:

```json
{
  "trustauthority_api_url": "https://api.trustauthority.intel.com",
  "trustauthority_api_key": "<trustauthority attestation API key>",
  "nvgpu": {
    "nras_apikey": "<NRAS API key>"
  }
}
```

The complete configuration example above is illustrative; `cloud_provider` and `ak_certificate` are not used together.

## TPM and event-log evidence

The `token` and `evidence` commands can combine evidence from Intel TDX, a TPM, and event logs. Azure CVMs with Intel TDX use TDX measurements to back the integrity of the vTPM quote; specify both `--tdx` and `--tpm` to collect composite evidence. Physical TPMs and GCP vTPMs can collect TPM-only evidence, or combine TPM and TDX evidence when both are available.

Collecting evidence from all relevant technologies can establish a chain of trust from hardware to the confidential VM. When both are available, collect and appraise Intel TDX and TPM evidence together.

### CCEL (`--ccel`)

The CCEL is included with TDX evidence when `--ccel` is set. The user must have read access to:

```text
/sys/firmware/acpi/tables/ccel
/sys/firmware/acpi/tables/data/ccel
```

The CCEL contains boot measurements extended to TDX RTMRs as well as TPM PCRs. See [UEFI 2.10, Section 38](https://uefi.org/specs/UEFI/2.10/38_Confidential_Computing.html).

### IMA (`--ima`)

The user collecting TPM evidence must have read access to `/sys/kernel/security/ima/ascii_runtime_measurements`. To grant read access to the `tss` group:

```sh
sudo chgrp tss /sys/kernel/security/ima/ascii_runtime_measurements
sudo chmod g+r /sys/kernel/security/ima/ascii_runtime_measurements
```

### UEFI event logs (`--evl`)

The user collecting TPM evidence must have read access to `/sys/kernel/security/tpm0/binary_bios_measurements`. To grant read access to the `tss` group:

```sh
sudo chgrp tss /sys/kernel/security/tpm0/binary_bios_measurements
sudo chmod g+r /sys/kernel/security/tpm0/binary_bios_measurements
```

## Command reference

```sh
./trustauthority-cli --help
./trustauthority-cli <command> --help
```

Available commands:

| Command | Description |
| --- | --- |
| `token` | Gets an attestation token from Intel Trust Authority. |
| `evidence` | Collects evidence from the TEE, TPM, or NVIDIA GPU and prints JSON. |
| `decrypt` | Decrypts an encrypted blob using a supplied private key. |
| `create-key-pair` | Creates an RSA 3072-bit key pair. |
| `provision-ak` | Provisions a physical TPM with an Intel Trust Authority-signed attestation key. |
| `provision-ak-template` | Creates a TPM attestation-key template. |
| `verify` | Verifies a signed Intel Trust Authority attestation token. |
| `version` | Displays the CLI version and build date. |

### `token`

Requests an attestation token. At least one evidence adapter is selected; if none of `--tdx`, `--tpm`, or `--nvgpu` is supplied, TDX evidence is selected by default.

```sh
trustauthority-cli token --config <config-file> \
  [--user-data <base64-data>] [--policy-ids <policy-ids>] \
  [--pub-path <public-key-path>] [--request-id <request-id>] \
  [--tdx] [--tpm] [--nvgpu] [--no-verifier-nonce] \
  [--token-signing-alg RS256|PS384] [--policy-must-match] \
  [--ima] [--evl] [--ccel]
```

Required option: `--config` (`-c`), the JSON configuration path.

Optional options:

- `--user-data` (`-u`): base64-encoded user data, up to 1 MiB.
- `--policy-ids` (`-p`): comma-separated policy IDs.
- `--pub-path` (`-f`): PEM public key to include as user data.
- `--request-id` (`-r`): caller-supplied request ID.
- `--token-signing-alg` (`-a`): `RS256` or `PS384` (the default).
- `--policy-must-match`: issue a token only when all policies match.
- `--tdx`, `--tpm`, `--nvgpu`: select evidence adapters.
- `--no-verifier-nonce`: omit the verifier nonce.
- `--ima`, `--evl`, `--ccel`: include IMA, UEFI, or CCEL measurements as described above.

Example:

```sh
sudo trustauthority-cli token --config config.json --user-data <base64-data> --tdx
```

### `evidence`

Collects evidence from the host and prints it as JSON. The JSON can be used as the body of a request to the Intel Trust Authority `/appraisal/v2/attest` endpoint or as reference data for an appraisal policy.

```sh
trustauthority-cli evidence --config <config-file> \
  [--tpm] [--tdx] [--nvgpu] [--no-verifier-nonce] \
  [--user-data <base64-data>] [--policy-ids <policy-ids>] \
  [--token-signing-alg RS256|PS384] [--policy-must-match] \
  [--ima] [--evl] [--ccel]
```

`--config` (`-c`) is required. `--tpm`, `--tdx`, and `--nvgpu` select evidence types; TDX is selected by default when none is specified. `--user-data`, `--policy-ids`, `--token-signing-alg`, `--policy-must-match`, `--no-verifier-nonce`, `--ima`, `--evl`, and `--ccel` have the same meanings as for `token`.

### `provision-ak`

Provisions a physical TPM with an attestation key signed by Intel Trust Authority and writes the AK certificate in PEM format to stdout. This command cannot be used with a vTPM. The `tpm` configuration section and the API settings must be configured first.

```sh
trustauthority-cli provision-ak --config config.json
```

Save the PEM certificate from stdout and set its `file://` path as `tpm.ak_certificate` before collecting physical TPM evidence.

### `provision-ak-template`

Creates a TPM attestation-key template. See command help for the available options:

```sh
trustauthority-cli provision-ak-template --help
```

### `verify`

Verifies a signed Intel Trust Authority attestation token. The configuration must include `trustauthority_url`.

```sh
trustauthority-cli verify --config config.json --token <JWT>
```

Required options are `--config` (`-c`) and `--token` (`-t`). For EU tenants, set `trustauthority_url` to `https://portal.eu.trustauthority.intel.com`.

### `version`

Displays the CLI version and build date:

```sh
trustauthority-cli version
```

### `decrypt`

Decrypts a base64- or base64url-encoded blob and writes the plaintext to stdout.

```sh
trustauthority-cli decrypt --key <base64-private-key> --in <encrypted-blob>
trustauthority-cli decrypt --key-path <private-key-path> --in <encrypted-blob>
```

`--in` is required. Exactly one of `--key` (`-k`) or `--key-path` (`-f`) must be supplied.

### `create-key-pair`

Creates an RSA 3072-bit key pair. The private key is written to stdout and the public key is written to the path supplied with `--pub-path`.

```sh
trustauthority-cli create-key-pair --pub-path <public-key-file>
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE) file.

<br><br>
---
**\*** Other names and brands may be claimed as the property of others.
