package main

// env CGO_CFLAGS_ALLOW="-f.*" go build

import (
	"fmt"
	"unsafe"

	"github.com/intel/amber/v1/client"
	"github.com/intel/amber/v1/client/sgx"
)

// #cgo CFLAGS: -I/opt/intel/sgxsdk/include -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fstack-protector-strong
// #cgo LDFLAGS: -lenclave -L.
// #include <stdint.h>
// #include "sgx_edger8r.h"
// #include "sgx_report.h"
// extern sgx_status_t enclave_create_report(sgx_enclave_id_t eid,
//												uint32_t* retval,
//												const sgx_target_info_t* p_qe3_target,
//												sgx_report_t* p_report);
//
//
//
//
// #include <stdio.h>
// sgx_status_t test_callback(sgx_enclave_id_t eid,
//								uint32_t* retval,
//								const sgx_target_info_t* p_qe3_target,
//								sgx_report_t* p_report)
// {
//		printf("EID: %ld\n", eid);
//		return 0;
// }
import "C"

func main() {
	client, err := client.New("https://10.80.213.35", "api-key-xyz")
	if err != nil {
		panic(err)
	}

	var eid uint64
	// status := sgx_create_enclave(&eid, ...)
	eid = 32

	adapter, err := sgx.NewAdapter(eid, unsafe.Pointer(C.test_callback)) //enclave_create_report
	if err != nil {
		panic(err)
	}

	token, err := client.CollectToken(adapter, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println(token)
}
