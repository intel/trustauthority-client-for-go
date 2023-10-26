# Intel® Trust Authority TDX CLI
An easy-to-use command line interface for attesting TDX TEE(TD) with Intel Trust Authority. The CLI will be installed and run inside the TD.

## Go Requirement

Use <b>go1.19 or newer</b>. Follow https://go.dev/doc/install for installation of Go.

## Installation

### Build
Compile Intel Trust Authority TDX CLI. This will generate `trustauthority-cli` binary in current directory:

```sh
cd tdx-cli/
make cli
```

## Unit Tests

To run the tests, run `cd tdx-cli && make test-coverage`

See the example test in `tdx-cli/token_test.go` for an example of a test.

## Usage

### To get list of all the available commands

```sh
trustauthority-cli --help
```
More info about a specific command can be found using
```sh
trustauthority-cli <command> --help
```

### To create RSA keypair

```sh
trustauthority-cli create-key-pair --pub-path <public key file path>
```

### To get Intel Trust Authority signed token

`token` command requires Intel Trust Authority configuration to be passed in json format
```json
{
    "trustauthority_api_url": "<trustauthority attestation api url>",
    "trustauthority_api_key": "<trustauthority attestation api key>"
}
```
Save this data in config.json file and invoke `token` command
```sh
trustauthority-cli token --config config.json --user-data <base64 encoded userdata> --policy-ids <comma separated trustauthority attestation policy ids> --no-eventlog
```
OR
```sh
trustauthority-cli token --config config.json --pub-path <public key file path> --policy-ids <comma separated trustauthority attestation policy ids> --no-eventlog
```

### To get TD quote with Nonce and UserData

```sh
trustauthority-cli quote --nonce <base64 encoded nonce> --user-data <base64 encoded userdata>
```

### To decrypt an encrypted blob

```sh
trustauthority-cli decrypt --key-path <private key file path> --in <base64 encoded encrypted blob>
```
OR
```sh
trustauthority-cli decrypt --key <base64 encoded private key> --in <base64 encoded encrypted blob>
```

### To verify Intel Trust Authority signed token

`verify` command requires Intel Trust Authority URL to be passed in json format
```json
{
    "trustauthority_url": "<trustauthority url>"
}
```
Save this data in config.json file and invoke `verify` command
```sh
trustauthority-cli verify --config config.json --token <attestation token in JWT format>
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
