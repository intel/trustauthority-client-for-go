# Intel® Trust Authority Attestation Client CLI with vTPM 

<p style="font-size: 0.875em;">· 08/22/2024 ·</p>

> [!NOTE]
> Intel® Trust Authority Attestation Client CLI with vTPM support is in limited preview status. Details of implementation and usage may change before general availability. Preview features are only available on the Intel Trust Authority pilot environment. Contact your Intel representative for access.

Intel® Trust Authority Attestation Client CLI ("client CLI") a CLI to attest an Intel TDX trust domain (TD) with Intel Trust Authority. The client CLI provides a core set of commands that apply to all TEEs, with minor differences in options and usage depending on the TEE or platform. This version of the client CLI supports composite attestation of an Azure confidential VM with Intel TDX and vTPM. 

For a complete description of client CLI commands and options, see [Attestation Client CLI](https://docs.trustauthority.intel.com/main/articles/integrate-go-tdx-cli.html) in the Intel Trust Authority documentation.


## Build the client CLI from source

- Use **Go 1.22 or newer**. Follow https://go.dev/doc/install for installation of Go.
- Ensure that you have the **build-essential** package and its dependencies installed. Follow the instructions below.

1. Install the required packages for your OS.
    1. Ubuntu:
    ```sh
    sudo apt install build-essential
    ```
    1. SUSE Linux:
    ```sh
    sudo zypper install git make
    ```

1. Get the code.
    ```sh
    git clone https://github.com/intel/trustauthority-client-for-go
    ```

1. Compile Intel Trust Authority attestation client CLI. This will generate a `trustauthority-cli` binary in the current directory.

    ```sh
    cd trustauthority-client-for-go/tdx-cli/
    make cli
    ```

### Unit Tests

To run the tests, run `cd tdx-cli && make test-coverage`. See the example test in `tdx-cli/token_test.go` for an example of a test.

## Usage

For detailed information about the client CLI, see [Attestation Client CLI](https://docs.trustauthority.intel.com/main/articles/integrate-go-tdx-cli.html) in the Intel Trust Authority documentation. The client CLI documentation includes information about installation, configuration, commands and options. The current preview versions of the CLI are included in the documentation. 

To get a list of all the available commands, run the following command:

```sh
./trustauthority-cli --help
```
More info about a specific command can be found using the `--help` option:

```sh
./trustauthority-cli <command> --help
```
## Code of Conduct and Contributing

See the [CONTRIBUTING](../CONTRIBUTING.md) file for information on how to contribute to this project. The project follows the [ Code of Conduct](../CODE_OF_CONDUCT.md).

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.

<br><br>
---
**\*** Other names and brands may be claimed as the property of others.