# Intel® Trust Authority TDX CLI
An easy-to-use command line interface for attesting TDX TEE(TD) with Intel Trust Authority. The CLI will be installed and run inside the TD.

## Install TDX CLI (with DCAP dependencies)
   ```sh
   curl -L https://raw.githubusercontent.com/intel/trustauthority-client-for-go/main/release/install-tdx-cli-dcap.sh | sudo bash -
   ```

## Install TDX CLI for Azure
   ```sh
   curl -L https://raw.githubusercontent.com/intel/trustauthority-client-for-go/main/release/install-tdx-cli-azure.sh | sudo bash -
   ```

## Install TDX CLI for GCP
   ```sh
   curl -L https://raw.githubusercontent.com/intel/trustauthority-client-for-go/main/release/install-tdx-cli-gcp.sh | sudo bash -
   ```
## Build CLI from Source

### Prerequisites

The default TDX CLI has dependency on Intel SGX DCAP. Install TDX Attestation library dev package from Intel SGX DCAP. Instructions follows.

#### For Ubuntu* OS
Install the Debian package for `libtdx-attest-dev` following these steps:

1. Add the following repository to your sources:
    * For Ubuntu* 20.04:
        ```sh
        echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
        ```
    * For Ubuntu* 22.04:
        ```sh
        echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
        ```
2. Get the Debian repo public key and add it to the list of trusted keys that are used by apt to authenticate packages:
    * For Ubuntu* 20.04:
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

#### For RHEL* OS
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

#### For SUSE* OS
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
    sudo zypper addrepo file://PATH_TO_LOCAL_REPO
    ```
6. Install all the latest packages using `sudo zypper --no-gpg-check install <package names>`
    ```sh
    sudo zypper --no-gpg-checks install libtdx-attest-devel 
    ```

#### Go Requirement

Use <b>go1.19 or newer</b>. Follow https://go.dev/doc/install for installation of Go.

### Build CLI
Compile Intel Trust Authority TDX CLI. This will generate `trustauthority-cli` binary in current directory:

```sh
cd tdx-cli/
make cli
```

### Unit Tests

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

### To create RSA keypair

```sh
./trustauthority-cli create-key-pair --pub-path <public key file path>
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
sudo ./trustauthority-cli token --config config.json --user-data <base64 encoded userdata> --policy-ids <comma separated trustauthority attestation policy ids>
```
OR
```sh
sudo ./trustauthority-cli token --config config.json --pub-path <public key file path> --policy-ids <comma separated trustauthority attestation policy ids>
```

### To get TD quote with Nonce and UserData

```sh
sudo ./trustauthority-cli quote --nonce <base64 encoded nonce> --user-data <base64 encoded userdata>
```

### To decrypt an encrypted blob

```sh
./trustauthority-cli decrypt --key-path <private key file path> --in <base64 encoded encrypted blob>
```
OR
```sh
./trustauthority-cli decrypt --key <base64 encoded private key> --in <base64 encoded encrypted blob>
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
./trustauthority-cli verify --config config.json --token <attestation token in JWT format>
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.
