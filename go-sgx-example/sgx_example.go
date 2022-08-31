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

// #cgo CFLAGS: -I/opt/intel/sgxsdk/include -I../minimal-enclave/ -fstack-protector-strong
// #cgo LDFLAGS: -lutils
// #include "sgx_urts.h"
// #include "Enclave_u.h"
// #include "utils.h"
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

	pubBytes, err := loadPublicKey(eid)
	if err != nil {
		panic(err)
	}

	adapter, err := sgx.NewAdapter(eid, pubBytes, unsafe.Pointer(C.enclave_create_report))
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

	fmt.Printf("Collected Attestation Token from Amber")

	err = client.VerifyToken(string(token))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Verified Attestation Token received from Amber")
}

func loadPublicKey(eid uint64) ([]byte, error) {
	// keySize holds the length of the key byte array returned from enclave
	var keySize C.uint32_t

	// keyBuf holds the bytes array of the key returned from enclave
	var keyBuf *C.uint8_t

	ret := C.get_public_key(C.ulong(eid), &keyBuf, &keySize)
	if ret != 0 {
		return nil, errors.New("failed to retrieve key from sgx enclave")
	}

	key := C.GoBytes(unsafe.Pointer(keyBuf), C.int(keySize))
	C.free_public_key(keyBuf)

	return key, nil
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
