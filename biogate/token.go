package biogate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// ApprovalToken is portable, verifiable proof that a named credential approved a
// specific request at a specific time. It is self-describing: KeyID is the
// public key, so any holder can check the signature. Whether to *trust* that key
// is a separate, caller-side decision.
type ApprovalToken struct {
	V          int       `json:"v"`
	Action     string    `json:"action"`
	Subject    string    `json:"subject"`
	Detail     string    `json:"detail,omitempty"`
	Method     Method    `json:"method"`
	ApprovedAt time.Time `json:"approved_at"`
	KeyID      string    `json:"key_id"`         // hex-encoded ed25519 public key
	Nonce      string    `json:"nonce"`          // 128-bit random, hex
	Agent      string    `json:"agent,omitempty"` // AAuth aa-agent+jwt binding this key to an agent identity (aauth signer)
	Sig        string    `json:"sig,omitempty"`  // base64 ed25519 signature over the canonical payload
}

// Errors from token verification.
var (
	ErrBadToken     = errors.New("biogate: malformed token")
	ErrBadSignature = errors.New("biogate: signature does not verify")
	ErrNoIdentity   = errors.New("biogate: token carries no AAuth agent identity")
)

// signingBytes is the canonical payload the signature covers: the token with an
// empty signature, marshalled deterministically (Go marshals struct fields in
// declaration order).
func (t ApprovalToken) signingBytes() ([]byte, error) {
	c := t
	c.Sig = ""
	return json.Marshal(c)
}

// Verify checks the token's signature against the public key embedded in KeyID.
// It proves integrity and authenticity, not trust: the caller decides whether
// KeyID is a key it recognizes.
func Verify(t *ApprovalToken) error {
	pub, err := hex.DecodeString(t.KeyID)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return ErrBadToken
	}
	sig, err := base64.StdEncoding.DecodeString(t.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrBadToken
	}
	msg, err := t.signingBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return ErrBadSignature
	}
	return nil
}

// Marshal renders the token as indented JSON.
func (t *ApprovalToken) Marshal() ([]byte, error) { return json.MarshalIndent(t, "", "  ") }

// ParseToken decodes a token from JSON.
func ParseToken(b []byte) (*ApprovalToken, error) {
	var t ApprovalToken
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, ErrBadToken
	}
	return &t, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
