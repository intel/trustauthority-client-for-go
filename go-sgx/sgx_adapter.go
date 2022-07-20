package sgx

import (
	"unsafe"
)

type SgxAdapter struct {
	EID            uint64
	ReportFunction unsafe.Pointer
}

func NewAdapter(eid uint64, reportFunction unsafe.Pointer) (*SgxAdapter, error) {
	return &SgxAdapter{
		EID:            eid,
		ReportFunction: reportFunction,
	}, nil
}
