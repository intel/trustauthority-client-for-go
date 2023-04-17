# Intel Project Amber Go TDX CLI
This is the beta version of Go TDX CLI for integrating with Intel Project Amber V1 API.

You can view Intel Project Amber API docs here: [https://intel.github.io/amber-docs/rest/overview/](https://intel.github.io/amber-docs/rest/overview/)

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
    ```
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

Use <b>go1.17 or newer</b>.

## Installation

### Build
Compile Amber Client TDX CLI. This will generate amber-cli binary in current directory:

```sh
cd amber-cli-tdx/
make cli
```

### Install prebuilt binary
Install the latest version of the CLI with the following commands:

```sh
go get github.com/intel/amber/v1/client/tdx-cli
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
amber-cli create-key-pair
```

## License

This client is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
