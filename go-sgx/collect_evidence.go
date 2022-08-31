package sgx

// #cgo CFLAGS: -I/opt/intel/sgxsdk/include -fstack-protector-strong
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
	"encoding/hex"
	"fmt"
	"unsafe"

	"github.com/intel/amber/v1/client"
	"github.com/pkg/errors"
)

func (adapter *SgxAdapter) CollectEvidence(nonce *client.SignedNonce) (*client.Evidence, error) {

	retVal := C.uint32_t(0)
	qe3_target := C.sgx_target_info_t{}
	p_report := C.sgx_report_t{}

	qe3_ret := C.sgx_qe_get_target_info(&qe3_target)
	if qe3_ret != 0 {
		return nil, errors.Errorf("sgx_qe_get_target_info return error code %x", qe3_ret)
	}

	var nonceValue []byte
	if nonce != nil {
		nonceValue = nonce.Nonce
		if nonce.Iat != nil && len(nonce.Iat) > 0 {
			nonceValue = append(nonceValue, nonce.Iat[:]...)
		}
	}

	status := C.get_report((C.report_fx)(adapter.ReportFunction),
		C.sgx_enclave_id_t(adapter.EID),
		&retVal,
		&qe3_target,
		(*C.uint8_t)(unsafe.Pointer(&nonceValue[0])),
		C.uint32_t(len(nonceValue)),
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

	fmt.Printf("Q: %s\n", hex.EncodeToString(quote_buffer))

	return &client.Evidence{
		Type:     0,
		Evidence: quote_buffer,
		UserData: adapter.uData,
	}, nil
}
