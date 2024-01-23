# Intel® Trust Authority TDX CLI
An easy-to-use command line interface for attesting Azure TDX TEE(TD) with Intel Trust Authority. The CLI is specifically built to work with Azure TDX stack and will be installed and run inside the TD.

## TPM2 Tools
TPM2 tools is required to read the TDX report data from vTPM. Install tpm2-tools package, e.g., on Ubuntu:
```sh
sudo apt install tpm2-tools libtss2-tcti-device0
```
On SUSE Linux
```sh
sudo zypper install tpm2.0-tools libtss2-tcti-device0   
```

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
./trustauthority-cli --help
```
More info about a specific command can be found using
```sh
./trustauthority-cli <command> --help
```

### To get Intel Trust Authority signed token

`token` command requires Intel Trust Authority configuration to be passed in json format
```json
{
    "trustauthority_api_url": "https://api.trustauthority.intel.com",
    "trustauthority_api_key": "<trustauthority attestation api key>"
}
```
Save this data in config.json file and invoke `token` command
```sh
sudo ./trustauthority-cli token --config config.json --user-data <base64 encoded userdata>  --no-eventlog
```


### To verify Intel Trust Authority signed token

`verify` command requires Intel Trust Authority URL to be passed in json format
```json
{
    "trustauthority_url": "https://portal.trustauthority.intel.com"
}
```
Save this data in config.json file and invoke `verify` command
```sh
trustauthority-cli verify --config config.json --token <attestation token in JWT format>
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
