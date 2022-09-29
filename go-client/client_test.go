package client

import (
	"crypto/tls"
	"testing"
)

func Test1(t *testing.T) {
	cfg := Config{
		TlsCfg: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	_, err := New(&cfg)
	if err == nil {
		t.Error(err)
	}
}
