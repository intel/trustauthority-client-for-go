---
last_updated: 01 February 2024
---

# Intel® Trust Authority TDX CLI
An easy-to-use command line interface for attesting TDX TEE(TD) with Intel Trust Authority. The CLI will be installed and run inside the TD.

### Before you begin
Make sure you have build essential and dependencies installed.
#### Ubuntu
```sh
sudo apt install build-essential
sudo snap install go --classic
```
#### SLES
```sh
sudo zypper install git make go
```

Note: make sure go is 1.19 or newer.
```sh
go version
```
### Get the code
Checkout the code
```sh
git clone https://github.com/intel/trustauthority-client -b gcp-tdx-preview
```

### Build CLI
Compile Intel Trust Authority TDX CLI. This will generate `trustauthority-cli` binary in current directory:

```sh
cd trustauthority-client/tdx-cli/
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
sudo ./trustauthority-cli token --config config.json --user-data <base64 encoded userdata>  --no-eventlog
```

### To verify Intel Trust Authority signed token
```sh
./trustauthority-cli verify --config config.json --token <attestation token in JWT format>
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
