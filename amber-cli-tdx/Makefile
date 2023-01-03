APPNAME := amber-cli

all: clean cli test test-coverage

cli:
	env GOOS=linux GOSUMDB=off CGO_CFLAGS_ALLOW="-f.*" \
	go build -o ${APPNAME}

test: 
	env GOOS=linux GOSUMDB=off CGO_CFLAGS_ALLOW="-f.*" \
	go test ./... --tags=test

test-coverage:
	env GOOS=linux GOSUMDB=off CGO_CFLAGS_ALLOW='-f.*' \
	go test ./... --tags=test -coverprofile=cover.out; go tool cover -func cover.out

clean:
	rm -rf ${APPNAME}
.PHONY: clean cli test test-coverage
