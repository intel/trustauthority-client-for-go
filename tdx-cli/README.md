# Intel® Trust Authority Attestation Client CLI

<p style="font-size: 0.875em;">· 01/20/2025 ·</p>

Intel® Trust Authority Attestation Client CLI ("client CLI") for Intel® Trust Domain Extensions (Intel® TDX) [**tdx-cli**](./tdx-cli) provides a CLI to attest an Intel TDX trust domain (TD) with Intel Trust Authority. The client CLI provides a core set of commands that apply to all TEEs, with minor differences in options and usage depending on the TEE or platform.

For a complete description of client CLI commands and options, see [Attestation Client CLI](https://docs.trustauthority.intel.com/main/articles/integrate-go-tdx-cli.html) in the Intel Trust Authority documentation.

## Install TDX CLI
   ```sh
   curl -sL https://raw.githubusercontent.com/intel/trustauthority-client-for-go/main/release/install-tdx-cli.sh | sudo bash -
   ```

### Verify the signature of the client CLI binary

To verify the signature of the client CLI binary downloaded using the bash script, follow these steps:

1. Extract public key from the certificate
```
openssl x509 -in /usr/bin/trustauthority-cli.cer -pubkey -noout > /tmp/public_key.pem
```

2. Create a hash of the binary
```
openssl dgst -out /tmp/binaryHashOutput -sha512 -binary /usr/bin/trustauthority-cli
```

3. Verify the signature 
```
openssl pkeyutl -verify -pubin -inkey /tmp/public_key.pem -sigfile /usr/bin/trustauthority-cli.sig -in /tmp/binaryHashOutput -pkeyopt digest:sha512 -pkeyopt rsa_padding_mode:pss
```

## Build the client CLI from source

- Use **Go 1.25 or newer**. Follow https://go.dev/doc/install for installation of Go.
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

### To get an Intel Trust Authority attestation token

The `token` command requires an Intel Trust Authority configuration to be passed in JSON format

```json
{
    "trustauthority_api_url": "https://api.trustauthority.intel.com",
    "trustauthority_api_key": "<trustauthority attestation api key>"
}
```
Save this data in a `config.json` file and then invoke the `token` command.

```sh
sudo trustauthority-cli token --config config.json --user-data <base64 encoded userdata> --no-eventlog
```
> [!NOTE]
> If running on Azure, include `"cloud_provider": "azure"` in `config.json` file
```json
{
    "cloud_provider": "azure",
    "trustauthority_api_url": "https://api.trustauthority.intel.com",
    "trustauthority_api_key": "<trustauthority attestation api key>"
}
```
> [!NOTE]
> If you are in the European Union (EU) region, use the following Intel Trust Authority API URL
```json
"trustauthority_api_url": "https://api.eu.trustauthority.intel.com"
```

### To verify an Intel Trust Authority attestation token

The `verify` command requires the Intel Trust Authority baseURL to be passed in JSON format.

```json
{
    "trustauthority_url": "https://portal.trustauthority.intel.com"
}
```
Save this data in config.json file and then invoke the `verify` command.

```sh
trustauthority-cli verify --config config.json --token <attestation token in JWT format>
```
> [!NOTE]
> If you are in the European Union (EU) region, use the following Intel Trust Authority URL
```json
"trustauthority_url": "https://portal.eu.trustauthority.intel.com"
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.

<br><br>
---
**\*** Other names and brands may be claimed as the property of others.
