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

### To get Intel Trust Authority signed token

```json
{
    "trustauthority_url": "https://portal.trustauthority.intel.com",
    "trustauthority_api_url": "https://api.trustauthority.intel.com",
    "trustauthority_api_key": "<trustauthority attestation api key>"
}
```
Save this data in a `config.json` file and then invoke the `token` command.

```sh
trustauthority-cli token --config config.json --user-data <base64 encoded userdata>  --no-eventlog
```

### To verify Intel Trust Authority signed token
```sh
./trustauthority-cli verify --config config.json --token <attestation token in JWT format>
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
