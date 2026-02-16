package client

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/intel/trustauthority-client/go-connector"
)

type TeeClient interface {
	Token() (string, error)
}

type attestClient struct {
	config    *connector.Config
	adapter   connector.EvidenceAdapter
	connector connector.Connector
}

type Config struct {
	TrustAuthorityUrl    string `json:"trustauthority_url"`
	TrustAuthorityApiUrl string `json:"trustauthority_api_url"`
	TrustAuthorityApiKey string `json:"trustauthority_api_key"`
}

func New(cfg *connector.Config, adp connector.EvidenceAdapter) (TeeClient, error) {
	return &attestClient{
		config:  cfg,
		adapter: adp,
	}, nil
}

func NewClient(adp connector.EvidenceAdapter) (teecli TeeClient, err error) {

	var configFile string
	flag.StringVar(&configFile, "config", "config.json", "Config file containing trustauthority details in JSON format")
	flag.Parse()

	configJson, err := os.ReadFile(configFile)
	if err != nil {
		return
	}

	var config Config
	err = json.Unmarshal(configJson, &config)
	if err != nil {
		return
	}

	if config.TrustAuthorityUrl == "" || config.TrustAuthorityApiUrl == "" || config.TrustAuthorityApiKey == "" {
		fmt.Println("Either Trust Authority URL, API URL or API Key is missing in config")
		os.Exit(1)
	}

	cfg := &connector.Config{
		TlsCfg: &tls.Config{
			InsecureSkipVerify: true,
		},
		BaseUrl: config.TrustAuthorityUrl,
		ApiUrl:  config.TrustAuthorityApiUrl,
		ApiKey:  config.TrustAuthorityApiKey,
	}
	return New(cfg, adp)
}

func (atclient *attestClient) Token() (tokenstr string, err error) {

	atclient.connector, err = connector.New(atclient.config)
	if err != nil {
		return
	}

	req := connector.GetNonceArgs{
		RequestId: "nonce_req",
	}
	resp, err := atclient.connector.GetNonce(req)
	if err != nil {
		panic(err)
	}

	evidence, err := atclient.adapter.CollectEvidence(append(resp.Nonce.Val, resp.Nonce.Iat[:]...))
	if err != nil {
		panic(err)
	}
	tokenargs := connector.GetTokenArgs{resp.Nonce, evidence, nil, "req1"}
	// dump.P(tokenargs)

	resp2, err := atclient.connector.GetToken(tokenargs)
	if err != nil {
		panic(err)
	}
	tokenstr = resp2.Token
	return
}
