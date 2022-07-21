package main

// env CGO_CFLAGS_ALLOW="-f.*" go build

import (
	"crypto/tls"
	"flag"
	"fmt"
	"unsafe"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/intel/amber/v1/client"
	"github.com/intel/amber/v1/client/sgx"
)

// #cgo CFLAGS: -I/opt/intel/sgxsdk/include -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fstack-protector-strong
// #cgo LDFLAGS: -L/usr/lib/x86_64-linux-gnu/ -lsgx_urts
// #include "sgx_urts.h"
// #include "Enclave_u.h"
import "C"

func main() {
	var policyId string
	cfg := client.Config{
		TlsCfg: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	flag.StringVar(&cfg.Url, "url", "", "URL of Amber SaaS")
	flag.StringVar(&cfg.ApiKey, "key", "", "Api Key for Amber")
	flag.StringVar(&policyId, "pid", "", "Policy id for Amber verification")
	flag.Parse()

	client, err := client.New(&cfg)
	if err != nil {
		panic(err)
	}

	ver, err := client.GetAmberVersion()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Amber Version: %+v\n", ver)

	eid, err := createSgxEnclave("enclave.signed.so")
	if err != nil {
		panic(err)
	}

	adapter, err := sgx.NewAdapter(eid, unsafe.Pointer(C.enclave_create_report))
	if err != nil {
		panic(err)
	}

	var policyIds []uuid.UUID
	if policyId != "" {
		policyIds = append(policyIds, uuid.MustParse(policyId))
	}

	token, err := client.CollectToken(adapter, policyIds)
	if err != nil {
		panic(err)
	}

	fmt.Println(token)
}

// Consider adding this as a utility function in go-sgx
func createSgxEnclave(enclavePath string) (uint64, error) {
	var status C.sgx_status_t
	eid := C.sgx_enclave_id_t(0)
	updated := C.int(0)
	token := C.sgx_launch_token_t{}

	status = C.sgx_create_enclave(C.CString(enclavePath),
		0,
		&token,
		&updated,
		&eid,
		nil)

	if status != 0 {
		return 0, errors.Errorf("Failed to create enclave: %x", status)
	}

	return uint64(eid), nil
}
