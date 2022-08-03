# Build
Install SGX dependencies
### Build enclave (libenclave.so)...
- git clone https://github.com/intel/SGXDataCenterAttestationPrimitives.git
- cd SGXDataCenterAttestationPrimitives/SampleCode/QuoteGenerationSample/
- make
- Copy App/Enclave_u.c and App/Enclave_u.h to go-sgx-example dir.

### Build sgxexample
- cd go-sgx-example
- env CGO_CFLAGS_ALLOW="-f.*" go build

sgxexample is in the go-sgx-example dir.

# Run on SGX Host
- scp sgxexample enclave.signed.so root@{{SGX Host}}:/tmp

- Install dcap dependencies...
    ```
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
    apt-get update 
    apt-get update && apt-get install -y --no-install-recommends \
        libsgx-urts \
        libsgx-dcap-default-qpl \
        libsgx-dcap-quote-verify
    ```

- Register host with TCS

- Edit /etc/sgx_default_qcnl.conf
    ```
    PCCS_URL=https://{{AMBER IP}}/tcs/v1/sgx/
    USE_SECURE_CERT=false
    ```

- Run example...
    ```
    env no_proxy={{AMBER IP}} ./sgxexample -url=https://{{AMBER IP}}
    ```