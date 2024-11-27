# Gramine-SGX Integration MVP

## Deploy Gramine-SGX

https://gramine.readthedocs.io/

## Build

```sh
make SGX=1
```

## Config

1) Visit https://trustauthority.intel.com/ to get a API key.
2) Set the API key in lib-app/config.json file

## Run

```sh
gramine-sgx app
```

## Clean

```sh
make clean
```
