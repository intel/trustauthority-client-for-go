module github.com/intel/amber-client/go-sgx

go 1.20

require (
	github.com/intel/amber-client/go-client v0.0.0
	github.com/pkg/errors v0.9.1
)

require (
	github.com/golang-jwt/jwt/v4 v4.4.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
)

replace github.com/intel/amber-client/go-client => ../go-client
