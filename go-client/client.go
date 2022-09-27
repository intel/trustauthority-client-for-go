package client

import (
	"crypto/tls"
	"net/url"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type AmberClient interface {
	GetAmberVersion() (*Version, error)
	GetNonce() (*Nonce, error)
	GetToken(nonce *Nonce, policyIds []uuid.UUID, evidence *Evidence) ([]byte, error)
	CollectToken(adapter EvidenceAdapter, policyIds []uuid.UUID) ([]byte, error)
	VerifyToken(string) (*jwt.Token, error)
}

type EvidenceAdapter interface {
	CollectEvidence(nonce []byte) (*Evidence, error)
}

type Evidence struct {
	Type     uint32
	Evidence []byte
	UserData []byte
}

type Config struct {
	Url    string
	TlsCfg *tls.Config
	ApiKey string
	url    *url.URL
}

type Nonce struct {
	Val       []byte `json:"val"`
	Iat       []byte `json:"iat"`
	Signature []byte `json:"signature"`
}

type Version struct {
	Name      string `json:"name"`
	SemVer    string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
}

func New(cfg *Config) (AmberClient, error) {
	var err error
	cfg.url, err = url.ParseRequestURI(cfg.Url)
	if err != nil {
		return nil, err
	}

	return &amberClient{
		cfg: cfg,
	}, nil
}

type amberClient struct {
	cfg *Config
}
