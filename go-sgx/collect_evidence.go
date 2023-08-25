/*
 *   Copyright (c) 2022 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package sgx

// #cgo CFLAGS: -I/opt/intel/sgxsdk/include -fstack-protector-strong
// #cgo LDFLAGS: -lsgx_dcap_ql -lsgx_urts -ldl -lpthread -L/usr/lib/x86_64-linux-gnu/
//
// #include <stdlib.h>
// #include "sgx_urts.h"
// #include "sgx_dcap_ql_wrapper.h"
// #include "sgx_report.h"
//
// typedef sgx_status_t (*report_fx) (sgx_enclave_id_t eid,
//										uint32_t* retval,
//										const sgx_target_info_t* p_qe3_target,
//										uint8_t* nonce,
//										uint32_t nonce_size,
//										sgx_report_t* p_report);
//
// int get_report(report_fx fx,
//					sgx_enclave_id_t eid,
//					uint32_t* retval,
//					const sgx_target_info_t* p_qe3_target,
//					uint8_t* nonce,
//					uint32_t nonce_size,
//					sgx_report_t* p_report)
// {
//		return fx(eid, retval, p_qe3_target, nonce, nonce_size, p_report);
// }
import "C"
import (
	"unsafe"

	"github.com/intel/trustconnector/go-connector"
	"github.com/pkg/errors"
)

// CollectEvidence is used to get SGX quote using DCAP Quote Generation library
func (adapter *sgxAdapter) CollectEvidence(nonce []byte) (*connector.Evidence, error) {

	retVal := C.uint32_t(0)
	qe3_target := C.sgx_target_info_t{}
	p_report := C.sgx_report_t{}

	qe3_ret := C.sgx_qe_get_target_info(&qe3_target)
	if qe3_ret != 0 {
		return nil, errors.Errorf("sgx_qe_get_target_info return error code %x", qe3_ret)
	}

	noncePtr := (*C.uint8_t)(C.CBytes(nonce))
	defer C.free(unsafe.Pointer(noncePtr))

	status := C.get_report((C.report_fx)(adapter.ReportFunction),
		C.sgx_enclave_id_t(adapter.EID),
		&retVal,
		&qe3_target,
		noncePtr,
		C.uint32_t(len(nonce)),
		&p_report)

	if status != 0 {
		return nil, errors.Errorf("Report callback returned error code %x", status)
	}

	if retVal != 0 {
		return nil, errors.Errorf("Report retval returned %x", status)
	}

	var quote_size C.uint32_t
	qe3_ret = C.sgx_qe_get_quote_size(&quote_size)
	if qe3_ret != 0 {
		return nil, errors.Errorf("sgx_qe_get_quote_size return error code %x", qe3_ret)
	}

	quote_buffer := make([]byte, quote_size)

	qe3_ret = C.sgx_qe_get_quote(&p_report, quote_size, (*C.uint8_t)(unsafe.Pointer(&quote_buffer[0])))
	if qe3_ret != 0 {
		return nil, errors.Errorf("sgx_qe_get_quote return error code %x", qe3_ret)
	}

	return &connector.Evidence{
		Type:     0,
		Evidence: quote_buffer,
		UserData: adapter.uData,
	}, nil
}
