package client

import (
	"testing"
)

func Test1(t *testing.T) {
	aac, err := NewAmberClient("https://10.80.213.35", "xyz")
	if err != nil {
		t.Fatal(err)
	}

	defer aac.Close()

	ver, err := aac.GetAmberVersion()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%+v", ver)
}
