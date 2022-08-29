package client

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type verifierKey struct {
	pubKey  crypto.PublicKey
	expTime time.Time
}

var pubKeyMap map[string]verifierKey

type MatchingCertNotFoundError struct {
	KeyId string
}

func (e MatchingCertNotFoundError) Error() string {
	return fmt.Sprintf("certificate with matching public key not found. kid (key id) : %s", e.KeyId)
}

type MatchingCertJustExpired struct {
	KeyId string
}

func (e MatchingCertJustExpired) Error() string {
	return fmt.Sprintf("certificate with matching public key just expired. kid (key id) : %s", e.KeyId)
}

type Token struct {
	jwtToken       *jwt.Token
	standardClaims *jwt.StandardClaims
}

type tokenRequest struct {
	Quote       []byte      `json:"quote"`
	SignedNonce SignedNonce `json:"signed_nonce"`
	UserData    []byte      `json:"user_data"`
	PolicyIds   []uuid.UUID `json:"policy_ids,omitempty"`
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

func (client *amberClient) VerifyToken(token *jwt.Token) error {
	err := validateToken(strings.TrimSpace(token.Raw))
	if err != nil {
		return err
	}

	return nil
}

func validateToken(tokenString string) error {
	token := Token{}
	token.standardClaims = &jwt.StandardClaims{}
	_, err := jwt.ParseWithClaims(tokenString, token.standardClaims, func(token *jwt.Token) (interface{}, error) {

		pubKeyMap = make(map[string]verifierKey)
		if keyIDValue, keyIDExists := token.Header["kid"]; keyIDExists {

			keyIDString, ok := keyIDValue.(string)
			if !ok {
				return nil, fmt.Errorf("kid (key id) in jwt header is not a string : %v", keyIDValue)
			}

			if matchPubKey, found := pubKeyMap[keyIDString]; !found {
				return nil, &MatchingCertNotFoundError{keyIDString}
			} else {
				// if the certificate just expired.. we need to return appropriate error
				// so that the caller can deal with it appropriately
				now := time.Now()
				if now.After(matchPubKey.expTime) {
					return nil, &MatchingCertJustExpired{keyIDString}
				}
				return matchPubKey.pubKey, nil
			}

		} else {
			return nil, fmt.Errorf("kid (key id) field missing in token. field is mandatory")
		}
	})

	if err != nil {
		if jwtErr, ok := err.(*jwt.ValidationError); ok {
			switch e := jwtErr.Inner.(type) {
			case *MatchingCertNotFoundError, *MatchingCertJustExpired:
				return e
			}
			return jwtErr
		}
		return err
	}

	return nil
}
