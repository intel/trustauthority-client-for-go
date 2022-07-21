module github.com/intel/amber/v1/sgxexample

go 1.17

require (
	github.com/intel/amber/v1/client v0.0.0
	github.com/intel/amber/v1/client/sgx v0.0.0
	github.com/pkg/errors v0.9.1
)

replace github.com/intel/amber/v1/client => ../go-client

replace github.com/intel/amber/v1/client/sgx => ../go-sgx

require (
	github.com/golang-jwt/jwt/v4 v4.4.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
)
