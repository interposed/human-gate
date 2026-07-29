package biogate

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// ed25519Signer signs ApprovalTokens with an ed25519 key. This is the default,
// dependency-free proof. A richer signer (for example one backed by the
// interpose identity stack / aauth) can replace it by implementing Signer.
type ed25519Signer struct {
	priv  ed25519.PrivateKey
	keyID string
}

// NewEphemeralSigner mints a fresh in-memory key. Tokens verify within the
// process but not across runs. Use LoadOrCreateSigner for a stable identity.
func NewEphemeralSigner() (Signer, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return &ed25519Signer{priv: priv, keyID: hex.EncodeToString(pub)}, nil
}

// LoadOrCreateSigner loads an ed25519 seed from path, creating it (0600) if it
// does not exist. The parent directory is created if needed.
func LoadOrCreateSigner(path string) (Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != ed25519.SeedSize {
			return nil, errors.New("biogate: key file has wrong size")
		}
		priv := ed25519.NewKeyFromSeed(b)
		pub := priv.Public().(ed25519.PublicKey)
		return &ed25519Signer{priv: priv, keyID: hex.EncodeToString(pub)}, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv.Seed(), 0o600); err != nil {
		return nil, err
	}
	return &ed25519Signer{priv: priv, keyID: hex.EncodeToString(pub)}, nil
}

func (s *ed25519Signer) KeyID() string { return s.keyID }

func (s *ed25519Signer) Sign(req Request, m Method, at time.Time) (*ApprovalToken, error) {
	tok := &ApprovalToken{
		V:          1,
		Action:     req.Action,
		Subject:    req.Subject,
		Detail:     req.Detail,
		Method:     m,
		ApprovedAt: at.UTC().Truncate(time.Second),
		KeyID:      s.keyID,
		Nonce:      randHex(16),
	}
	msg, err := tok.signingBytes()
	if err != nil {
		return nil, err
	}
	tok.Sig = base64Std(ed25519.Sign(s.priv, msg))
	return tok, nil
}
