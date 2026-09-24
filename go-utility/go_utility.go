package utility

import (
	"github.com/intel/trustauthority-client/go-client"
	"github.com/intel/trustauthority-client/go-gramine"
)

func GraToken(udata []byte) (token string, err error) {

	adp, err := gramine.NewEvidenceAdapter(udata)
	if err != nil {
		return
	}

	cli, err := client.NewClient(adp)
	if err != nil {
		return
	}

	token, err = cli.Token()
	if err != nil {
		return
	}
	return
}
