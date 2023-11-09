---
last_updated: 01 February 2024
---

# Intel® Trust Authority CLI for Intel TDX

Intel® Trust Authority CLI for Intel® Trust Domain Extensions (Intel® TDX) [**tdx-cli**](./tdx-cli) provides a CLI to attest an Intel TDX trust domain (TD) with Intel Trust Authority. **tdx-cli** requires **go-connector**, and **go-tdx**. See the [README](./tdx-cli/README.md) for details.

For more information, see [Intel Trust Authority CLI for Intel TDX](https://docs.trustauthority.intel.com/main/articles/integrate-go-tdx-cli.html) in the Intel Trust Authority documentation.

## Installation
   ```sh
   curl -sL https://raw.githubusercontent.com/intel/trustauthority-client-for-go/main/release/install-tdx-cli-azure.sh | sudo bash -
   ```

### Note
To verify the signature of TDX CLI binary downloaded using above bash scrpt, perform the following steps.

1. Extract public key from the certificate
```
openssl x509 -in /usr/bin/trustauthority-cli.cer -pubkey -noout > /tmp/public_key.pem
```

2. Create a hash of the binary
```
openssl dgst -out /tmp/binaryHashOutput -sha512 -binary /usr/bin/trustauthority-cli
```

3.Verify the signature 
```
openssl pkeyutl -verify -pubin -inkey /tmp/public_key.pem -sigfile /usr/bin/trustauthority-cli.sig -in /tmp/binaryHashOutput -pkeyopt digest:sha512 -pkeyopt rsa_padding_mode:pss
```


## Build CLI from Source

### Prerequisites

- Use **Go 1.19 or newer**. Follow https://go.dev/doc/install for installation of Go.

### Build CLI
Compile Intel Trust Authority TDX CLI. This will generate `trustauthority-cli` binary in current directory:

```sh
cd tdx-cli/
make cli
```

### Unit Tests

To run the tests, run `cd tdx-cli && make test-coverage`. See the example test in `tdx-cli/token_test.go` for an example of a test.

## Usage

### To get a list of all the available commands

```sh
./trustauthority-cli --help
```
More info about a specific command can be found using
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
sudo ./trustauthority-cli token --config config.json --user-data <base64 encoded userdata>  --no-eventlog
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
./trustauthority-cli verify --config config.json --token <attestation token in JWT format>
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
