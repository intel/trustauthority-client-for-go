## Build minimal-enclave...
- Install C development tools, go compiler, etc. (TBD)
- Install SGX SDK (TBD)
- cd minimal-enclave --> make --> produces "enclave.signed.so"

## Build go "sgxexample"...
- Install SGX dependencies (ubuntu)
    ```
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
    apt-get update
    apt-get install -y --no-install-recommends \
        libsgx-urts \
        libsgx-dcap-default-qpl \
        libsgx-dcap-quote-verify \
        libsgx-dcap-quote-verify-dev
    ```
- cp minimal-enclave/Enclave_u.* go-sgx-example/
- cd go-sgx-example
- env CGO_CFLAGS_ALLOW="-f.*" go build --> produces "sgxexample"

## Run on SGX Host
- scp go-sgx-example/sgxexample root@{{SGX Host}}:/tmp
- scp minimal-enclave/enclave.signed.so root@{{SGX Host}}:/tmp

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