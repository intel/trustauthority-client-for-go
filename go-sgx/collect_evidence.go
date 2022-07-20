package sgx

// #cgo CFLAGS: -I/opt/intel/sgxsdk/include -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fstack-protector-strong
// #cgo LDFLAGS: -lsgx_dcap_ql -lsgx_urts -ldl -lpthread -L/usr/lib/x86_64-linux-gnu/
//
// #include "sgx_urts.h"
// #include "sgx_tcrypto.h"
// #include "sgx_dcap_ql_wrapper.h"
// #include "sgx_quote_3.h"
//
// #include <stdint.h>
// #include "sgx_edger8r.h"
// #include "sgx_report.h"
// typedef sgx_status_t (*report_fx) (sgx_enclave_id_t eid,
// 											uint32_t* retval,
//											const sgx_target_info_t* p_qe3_target,
//											sgx_report_t* p_report);
//
// int get_report(report_fx fx,
//					sgx_enclave_id_t eid,
//					uint32_t* retval,
//					const sgx_target_info_t* p_qe3_target,
//					sgx_report_t* p_report)
// {
//		return fx(eid, retval, p_qe3_target, p_report);
// }
import "C"
import (
	"github.com/intel/amber/v1/client"
	"github.com/pkg/errors"
)

func (adapter *SgxAdapter) CollectEvidence(nonce *client.SignedNonce) (*client.Evidence, error) {
	// Call report callback
	// Generate a quote
	// Create/return evidence structure

	//qe3_ret := C.quote3_error_t(0)
	retVal := C.uint32_t(0)
	qe3_target := C.sgx_target_info_t{}
	p_report := C.sgx_report_t{}

	//qe3_ret = sgx_qe_get_target_info(&qe3_target)

	status := C.get_report((C.report_fx)(adapter.ReportFunction),
		C.sgx_enclave_id_t(adapter.EID),
		&retVal,
		&qe3_target,
		&p_report)

	if status != 0 {
		return nil, errors.Errorf("Report callback returned error code %x", status)
	}

	// sgx_qe_get_quote_size
	// sgx_qe_get_quote ==> Evidence structure

	return nil, nil
}
