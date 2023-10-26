---
last_updated: 01 February 2024
---

## Go Requirement

Use <b>go1.19 or newer</b>. Follow https://go.dev/doc/install for installation of Go.

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

### To create an RSA key pair

```sh
./trustauthority-cli create-key-pair --pub-path <public key file path>
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
trustauthority-cli token --config config.json --user-data <base64 encoded userdata> --policy-ids <comma separated trustauthority attestation policy ids> --no-eventlog
```
OR
```sh
trustauthority-cli token --config config.json --pub-path <public key file path> --policy-ids <comma separated trustauthority attestation policy ids> --no-eventlog
```

### To get a TD quote with a nonce and user data

```sh
sudo ./trustauthority-cli quote --nonce <base64 encoded nonce> --user-data <base64 encoded userdata>
```

### To decrypt an encrypted blob

The decrypt command uses SHA256 as the hash algorithm.

```sh
./trustauthority-cli decrypt --key-path <private key file path> --in <base64 encoded encrypted blob>
```
OR
```sh
./trustauthority-cli decrypt --key <base64 encoded private key> --in <base64 encoded encrypted blob>
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
