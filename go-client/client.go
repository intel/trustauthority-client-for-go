package client

//
// Install prereqs:  dcap, curl, ...
// Build or get amber client libraries (can this be apt-get?)
// helm install taas-ra --version v0.1.0-f65840c cassini-harbor/taas-ra -n taas -f ../dev-aio-values.yaml
//
import (
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type AmberClient interface {
	GetAmberVersion() (*Version, error)
	GetNonce() (*SignedNonce, error)
	GetToken(nonce *SignedNonce, policyIds []uuid.UUID, evidence Evidence) (*jwt.Token, error)
	CollectToken(adapter EvidenceAdapter, policyIds []uuid.UUID) (*jwt.Token, error)
}

type EvidenceAdapter interface {
	CollectEvidence(nonce *SignedNonce) (*Evidence, error)
}

type Evidence struct {
	Type                  uint32
	EvidenceLength        uint32
	Evidence              []byte
	EnclaveHeldDataLength uint32
	EnclaveHeldData       []byte
}

type SignedNonce struct {
	Nonce     []byte `json:"nonce"`
	Signature []byte `json:"signature"`
}

type Version struct {
	Name      string `json:"name"`
	SemVer    string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
}
