---
last_updated: 12 Sep 2024
---

# Intel® Trust Authority Azure SEVSNP CLI

The Intel® Trust Authority Azure SEVSNP CLI is a command line interface for attesting a Azure SEV-SNP CVM with Intel Trust Authority. The CLI must be installed and run inside the Azure SEV-SNP CVM. 

**The sevsnp-cli and go-sevsnp are exclusive beta preview features that are designed to work only within the Intel® Trust Authority Pilot environment. To access these features, you must have a service offer for the Intel® Trust Authority Pilot. The development of this branch is ongoing, and we encourage you to report any issues you encounter to the product team.**

## Go Requirement

Use <b>go1.22 or newer</b>. Follow https://go.dev/doc/install for installation of Go.

## Build CLI from Source

### Install tpm2-tools
```sh
sudo apt-get update
sudo apt-get install tpm2-tools
```

### Get the code
Checkout the code
```sh
git clone -b azure-sevsnp-preview https://github.com/intel/trustauthority-client-for-go
```

### Build
Use the following command to compile the Intel Trust Authority Azure SEVSNP CLI. This command generates the `trustauthority-sevsnp-cli` binary in current directory:

```sh
cd trustauthority-client-for-go/sevsnp-cli/
make cli
```

## Usage

### To get a list all the available commands

```sh
trustauthority-sevsnp-cli --help
```

More info about a specific command can be found using the following command.

```sh
trustauthority-sevsnp-cli <command> --help
```

### To get an Intel Trust Authority signed token

The `token` command requires the Intel Trust Authority configuration to be passed in json format.

```json
{
    "trustauthority_api_url": "https://api.pilot.trustauthority.intel.com",
    "trustauthority_api_key": "<trustauthority attestation api key>"
}
```

Save this data in config.json file and invoke the `token` command.

```sh
sudo ./trustauthority-sevsnp-cli token --config config.json --user-data <base64 encoded userdata> --policy-ids <comma separated trustauthority attestation policy ids>
```

### To get the SEVSNP report with a nonce and userData

```sh
sudo ./trustauthority-sevsnp-cli report --nonce <base64 encoded nonce> --user-data <base64 encoded userdata>
```

### To verify an Intel Trust Authority signed token

`verify` command requires Intel Trust Authority URL to be passed in json format.

```json
{
    "trustauthority_url": "https://portal.pilot.trustauthority.intel.com"
}
```

Save this data in a config.json file and invoke the `verify` command.

```sh
./trustauthority-sevsnp-cli verify --config config.json --token <attestation token in JWT format>
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.