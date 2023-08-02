# Intel Project Amber Go TDX CLI
This is the beta version of Go TDX CLI for integrating with Intel Project Amber V1 API.

## Prerequisites

The Amber Client TDX CLI has dependency on Intel SGX DCAP. Install TDX Attestation library devel packages from Intel SGX DCAP.

### For Ubuntu* OS
Install the Debian package for `libtdx-attest-dev` following these steps:

1. Add the following repository to your sources:
    * For Ubuntu* 18.04:
        ```sh
        echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
        ```
    * For Ubuntu* 20.04:
        ```sh
        echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
        ```
    * For Ubuntu* 22.04:
        ```sh
        echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
        ```
2. Get the Debian repo public key and add it to the list of trusted keys that are used by apt to authenticate packages:
    * For Ubuntu* 18.04 and Ubuntu* 20.04:
        ```sh
        wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add
        ```
    * For Ubuntu* 22.04:
        ```sh
        wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
        cat intel-sgx-deb.key | sudo tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
        ```
3. Update apt and install the *libtdx-attest-dev* package:
    ```sh
    sudo apt-get update
    sudo apt-get install libtdx-attest-dev
    ```

### For RHEL* OS
Install the RPM package for `libtdx-attest-devel` following these steps:

1. Find RPM packages for DCAP libraries and services, which are currently provided in a single TAR archive at
    ```sh
    https://download.01.org/intel-sgx/latest/linux-latest/distro/<distro>/
    ```
2. Download the file `sgx_rpm_local_repo.tgz` to a selected folder, for example `/opt/intel`
    ```sh
    cd /opt/intel
    sudo wget https://download.01.org/intel-sgx/latest/linux-latest/distro/<distro>/sgx_rpm_local_repo.tgz
    ```
3. Verify the downloaded repo file with the SHA value in this file:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/SHA256SUM_dcap_<version>.cfg
    ```sh
    sha256sum sgx_rpm_local_repo.tgz
    ```
4. Expand the archive:
    ```sh
    sudo tar xvf sgx_rpm_local_repo.tgz
    ```
5. Add the RPM local repository to your local repository list
    ```sh
    sudo yum-config-manager --add-repo file://PATH_TO_LOCAL_REPO
    ```
6. Install all the latest packages using `sudo dnf --nogpgcheck install <package names>`
    ```sh
    sudo dnf --nogpgcheck install libtdx-attest-devel
    ```

## Go Requirement

Use <b>go1.19 or newer</b>. Follow https://go.dev/doc/install for installation of Go.

## Installation

### Build
Compile Amber Client TDX CLI. This will generate amber-cli binary in current directory:

```sh
cd amber-cli-tdx/
make cli
```

## Usage

### To get a list of all the available commands

```sh
amber-cli --help
```
More info about a specific command can be found using
```sh
amber-cli <command> --help
```

### To create RSA keypair

```sh
amber-cli create-key-pair --key-path <private key file path>
```

### To get a Amber signed token

`token` command requires Amber properties to be passed in json format
```json
{
    "amber_api_url": "<amber attestation api url>",
    "amber_api_key": "<amber attestation api key>"
}
```
Save this data in config.json file and invoke `token` command
```sh
amber-cli token --config config.json --user-data <base64 encoded userdata> --policy-ids <comma separated amber attestation policy ids>
```
OR
```sh
amber-cli token --config config.json --pub-path <public key file path> --policy-ids <comma separated amber attestation policy ids>
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
