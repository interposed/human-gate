package humangate

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
	WebAuthn   *WebAuthnProof `json:"webauthn,omitempty"` // hardware-key assertion proof (fido2 approver, option B)
	Sig        string    `json:"sig,omitempty"`  // base64 ed25519 signature over the canonical payload (aauth/ed25519 signers)
}

// WebAuthnProof is a CTAP2 assertion that a registered hardware key produced when
// a human tapped it. The signature covers AuthData || ClientHash, where
// ClientHash is sha256 of the approval's canonical core, so it binds the tap to
// this exact approval. Self-contained: it carries the credential public key.
type WebAuthnProof struct {
	CredentialID []byte `json:"cred_id"`
	PubKey       []byte `json:"pub_key"`
	Alg          int    `json:"alg"` // COSE alg (-8 EdDSA, -7 ES256)
	AuthData     []byte `json:"auth_data"`
	ClientHash   []byte `json:"client_hash"`
	Sig          []byte `json:"sig"`
}

// Errors from token verification.
var (
	ErrBadToken     = errors.New("humangate: malformed token")
	ErrBadSignature = errors.New("humangate: signature does not verify")
	ErrNoIdentity   = errors.New("humangate: token carries no AAuth agent identity")
)

// signingBytes is the canonical payload the signature covers: the token with an
// empty signature, marshalled deterministically (Go marshals struct fields in
// declaration order).
func (t ApprovalToken) signingBytes() ([]byte, error) {
	c := t
	c.Sig = ""
	return json.Marshal(c)
}

// challengeCore is the canonical approval core that a hardware assertion binds:
// the token with the proof/identity/signature fields cleared.
func (t ApprovalToken) challengeCore() ([]byte, error) {
	c := t
	c.Sig = ""
	c.Agent = ""
	c.WebAuthn = nil
	return json.Marshal(c)
}

// Verify checks the token's proof. For a hardware (WebAuthn) token it verifies
// the assertion binds this approval; otherwise it verifies the detached ed25519
// signature against the public key in KeyID. It proves integrity and
// authenticity, not trust: the caller decides whether the key is recognized.
func Verify(t *ApprovalToken) error {
	if t.WebAuthn != nil {
		return verifyWebAuthn(t)
	}
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

// SignerKey returns the token's effective ed25519 signing identity, the key a
// verifier binds against a known set of owner keys. It handles both token
// shapes:
//
//   - an ed25519/aauth token (Sig + KeyID): the ed25519 public key in KeyID;
//   - a WebAuthn/fido2 token (ApproveAndSign, no top-level Sig): the credential
//     public key in WebAuthn.PubKey, when that credential is an EdDSA (Ed25519)
//     key (COSE alg -8). An ES256 (P-256) credential is a valid key but not an
//     ed25519 identity, so this returns an error rather than a false match.
//
// It does NOT itself verify the token: call Verify first. The error cases are a
// malformed KeyID and a non-Ed25519 credential.
func (t *ApprovalToken) SignerKey() (ed25519.PublicKey, error) {
	if t.WebAuthn != nil {
		return webAuthnEd25519Key(t.WebAuthn)
	}
	raw, err := hex.DecodeString(t.KeyID)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrBadToken
	}
	return ed25519.PublicKey(raw), nil
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
