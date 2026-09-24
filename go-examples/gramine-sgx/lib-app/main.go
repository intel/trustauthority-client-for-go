package main

import (
	"crypto/rand"
	"fmt"

	"github.com/intel/trustauthority-client/go-utility"
)

func main() {

	// Generate a random user runtime data
	blk, err := GenRandomBytes(10)
	if err != nil {
		panic(err)
	}

	// Retrieve a token of Intel Trust Authority for this Gramine SGX enclave
	tk, err := utility.GraToken(blk)
	if err != nil {
		panic(err)
	}

	// Display the token
	fmt.Printf("\nTOKEN: %s\n", tk)

}

func GenRandomBytes(size int) (blk []byte, err error) {
	blk = make([]byte, size)
	_, err = rand.Read(blk)
	return
}
