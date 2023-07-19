# Intel Project Amber Go TDX CLI
This is the beta version of Go TDX CLI for integrating with Intel Project Amber V1 API.

## Go Requirement

Use <b>go1.17 or newer</b>.

## Installation

### Build
Compile Amber Client TDX CLI. This will generate amber-cli binary in current directory:

```sh
cd amber-cli-tdx/
make cli
```

## Usage

Amber Client TDX CLI exposes help option to get a list of all the
commands that it supports. More info about a command can be found using

```sh
amber-cli <command> --help
```

### To get a Amber signed token

```sh
export AMBER_URL=<amber api url>
export AMBER_API_KEY=<amber attestation api key>
amber-cli token --user-data <base64 encoded userdata> --policy-ids <comma separated amber attestation policy ids>
```
OR
```sh
amber-cli token --pub-path <public key file path> --policy-ids <comma separated amber attestation policy ids>
```

### To verify an Amber signed token

```sh
export AMBER_URL=<amber api url>
export AMBER_API_KEY=<amber attestation api key>
amber-cli verify --token-path <token file path>
```

### To get a TD quote with Nonce and UserData

```sh
amber-cli quote --nonce <base64 encoded nonce> --user-data <base64 encoded userdata>
```

### To decrypt an encrypted blob

```sh
amber-cli decrypt --key-path <private key file path> --in <base64 encoded encrypted blob>
```
OR
```sh
amber-cli decrypt --key <base64 encoded private key> --in <base64 encoded encrypted blob>
```

### To create RSA keypair

```sh
amber-cli create-key-pair --pub-path <public key file path>
```

## License

This client is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
