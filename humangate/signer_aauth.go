package humangate

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
)

// aauthSigner mints AAuth-native identity proof alongside the detached approval
// signature, both under one Ed25519 key. Every ApprovalToken it produces carries
// an aa-agent+jwt (draft-hardt-oauth-aauth-protocol) that binds the signing key
// to an agent identity, and a detached signature over the approval payload.
//
// This is the dogfood path: the same identity layer the interpose broker
// adopts. human-gate exercises github.com/aauth-dev/aauth-go in the open first.
type aauthSigner struct {
	agent *aauth.Agent
	priv  ed25519.PrivateKey // the signing key (aauth.Agent holds it as a crypto.Signer)
	keyID string             // hex(pub); also the ApprovalToken.KeyID
}

// NewAAuthSigner builds a self-hosted AAuth agent from a persistent Ed25519 key
// and an agent identifier such as "aauth:humangate@host". The one key signs both
// the approval payload and the aa-agent+jwt (it is the cnf.jwk).
func NewAAuthSigner(identifier string, priv ed25519.PrivateKey) (Signer, error) {
	id, err := aauth.ParseAgentIdentifier(identifier)
	if err != nil {
		return nil, err
	}
	ag, err := aauth.NewAgent(id, aauth.WithKey(priv), aauth.WithTokenTTL(time.Hour))
	if err != nil {
		return nil, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrBadToken
	}
	return &aauthSigner{agent: ag, priv: priv, keyID: hex.EncodeToString(pub)}, nil
}

func (s *aauthSigner) KeyID() string { return s.keyID }

func (s *aauthSigner) Sign(req Request, m Method, at time.Time) (*ApprovalToken, error) {
	idTok, err := s.agent.MintToken()
	if err != nil {
		return nil, err
	}
	tok := &ApprovalToken{
		V:          1,
		Action:     req.Action,
		Subject:    req.Subject,
		Detail:     req.Detail,
		Method:     m,
		ApprovedAt: at.UTC().Truncate(time.Second),
		KeyID:      s.keyID,
		Nonce:      randHex(16),
		Agent:      idTok,
	}
	msg, err := tok.signingBytes() // covers the identity token too
	if err != nil {
		return nil, err
	}
	tok.Sig = base64Std(ed25519.Sign(s.priv, msg))
	return tok, nil
}

// VerifyIdentity verifies the aa-agent+jwt carried in the token via AAuth and
// confirms it binds the same key that signed the approval. Verify alone proves
// integrity; VerifyIdentity additionally proves the AAuth agent identity.
func VerifyIdentity(ctx context.Context, t *ApprovalToken) (*aauth.AgentClaims, error) {
	if t.Agent == "" {
		return nil, ErrNoIdentity
	}
	// The approval signature must verify first: same key, real approval.
	if err := Verify(t); err != nil {
		return nil, err
	}
	claims, err := aauth.VerifyAgentToken(ctx, t.Agent, aauth.VerifyAgentTokenOptions{
		Resolver: aauth.SelfSignedResolver{},
	})
	if err != nil {
		return nil, err
	}
	// Bind: the identity token's key must be the key that signed the approval.
	if claims.Cnf.JWK == nil {
		return nil, ErrBadToken
	}
	tokPub, err := claims.Cnf.JWK.PublicKey()
	if err != nil {
		return nil, err
	}
	// aauth-go's JWK.PublicKey returns a crypto.PublicKey (Ed25519 or P-256);
	// an approval key is always Ed25519, so assert it before the key comparison.
	edPub, ok := tokPub.(ed25519.PublicKey)
	if !ok {
		return nil, ErrBadToken
	}
	pub, _ := hex.DecodeString(t.KeyID)
	if !edPub.Equal(ed25519.PublicKey(pub)) {
		return nil, ErrBadSignature
	}
	return claims, nil
}
