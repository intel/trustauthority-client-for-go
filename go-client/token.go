package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type tokenRequest struct {
	Quote       []byte      `json:"quote"`
	SignedNonce SignedNonce `json:"signed_nonce"`
	//UserData    []byte      `json:"user_data"`
	PolicyIds []uuid.UUID `json:"policy_ids,omitempty"`
	//TenantId    uuid.UUID   `json:"tenant_id"`
	//PolicyNames []string    `json:"policy_names,omitempty"`
	//EventLog    []byte      `json:"event_log,omitempty"`
}

func (client *amberClient) GetToken(nonce *SignedNonce, policyIds []uuid.UUID, evidence *Evidence) (*jwt.Token, error) {

	url := fmt.Sprintf("%s/appraisal/v1/appraise", client.cfg.Url)

	newRequest := func() (*http.Request, error) {
		tr := tokenRequest{
			Quote:       evidence.Evidence,
			SignedNonce: *nonce,
			PolicyIds:   policyIds,
		}

		body, err := json.Marshal(tr)
		if err != nil {
			return nil, err
		}

		return http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	}

	var headers = map[string]string{
		headerXApiKey:  client.cfg.ApiKey,
		"Accept":       "application/jwt",
		"Content-Type": "application/json",
	}

	var token *jwt.Token
	processResponse := func(resp *http.Response) error {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Failed to read body from %s: %s", url, err)
		}

		token, err = jwt.Parse(string(body), func(token *jwt.Token) (interface{}, error) {
			// // Don't forget to validate the alg is what you expect:
			// if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			// 	return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			// }

			// // hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
			// return hmacSampleSecret, nil
			return nil, nil
		})

		return nil
	}

	if err := doRequest(client.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
		return nil, err
	}

	return token, nil
}
