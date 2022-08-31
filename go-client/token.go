package client

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	UserData    []byte      `json:"user_data"`
	PolicyIds   []uuid.UUID `json:"policy_ids,omitempty"`
	//TenantId    uuid.UUID   `json:"tenant_id"`
	//PolicyNames []string    `json:"policy_names,omitempty"`
	//EventLog    []byte      `json:"event_log,omitempty"`
}

func (client *amberClient) GetToken(nonce *SignedNonce, policyIds []uuid.UUID, evidence *Evidence) ([]byte, error) {

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

	var attestationToken []byte

	processResponse := func(resp *http.Response) error {
		var err error
		attestationToken, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Errorf("Failed to read body from %s: %s", url, err)
		}
		return nil
	}

	if err := doRequest(client.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
		return nil, err
	}

	return attestationToken, nil
}

func (client *amberClient) VerifyToken(token string) error {
	var tokenSignCertUrl string
	var tokenSignCert []byte
	var key crypto.PublicKey

	var parsedToken *jwt.Token
	var err error

	var headers = map[string]string{
		"Accept":       "application/jwt",
		"Content-Type": "application/json",
	}

	parsedToken, err = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if err != nil {
			return nil, errors.Errorf("Failed to parse jwt token")
		}

		if keyIDValue, keyIDExists := parsedToken.Header["jku"]; keyIDExists {

			tokenSignCertUrl, ok := keyIDValue.(string)
			if !ok {
				return nil, errors.Errorf("jku in jwt header is not valid : %v", tokenSignCertUrl)
			}

		} else {
			return nil, fmt.Errorf("jku field missing in token. field is mandatory")
		}

		newRequest := func() (*http.Request, error) {
			return http.NewRequest(http.MethodGet, tokenSignCertUrl, nil)
		}

		processResponse := func(resp *http.Response) error {
			tokenSignCert, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				return errors.Errorf("Failed to read body from %s: %s", tokenSignCertUrl, err)
			}

			block, _ := pem.Decode(tokenSignCert)

			if block == nil {
				return errors.Errorf("Unable to decode pem bytes")
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				errors.Errorf("Failed to parse certificate")
			} else {
				var ok bool
				if key, ok = cert.PublicKey.(*rsa.PublicKey); ok {
					return nil
				}
			}

			return nil
		}
		if err := doRequest(client.cfg.TlsCfg, newRequest, nil, headers, processResponse); err != nil {
			return nil, err
		}

		return key, nil
	})

	return nil
}
