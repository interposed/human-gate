package humangatetest

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/interposed/human-gate/humangate"
	"github.com/interposed/human-gate/humangate/bridge"
)

func inSet(k ed25519.PublicKey, set []ed25519.PublicKey) bool {
	for _, a := range set {
		if k.Equal(a) {
			return true
		}
	}
	return false
}

// An aauth-signed approval's effective signing identity is its ed25519 key: it
// is authorized by a set that contains that key and refused by a set that does
// not. This is the owner-key binding interpose's create-gate relies on.
func TestSignerKeyAAuthAuthorizedSet(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s, err := humangate.NewAAuthSigner("aauth:humangate@test.local", priv)
	if err != nil {
		t.Fatalf("NewAAuthSigner: %v", err)
	}
	tok, err := humangate.RequireApproval(context.Background(), req("mock"),
		humangate.WithApprover(mockApprover{}), humangate.WithSigner(s))
	if err != nil {
		t.Fatal(err)
	}
	if err := humangate.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}

	got, err := tok.SignerKey()
	if err != nil {
		t.Fatalf("SignerKey: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatalf("SignerKey = %x, want signer pub %x", got, pub)
	}

	// A file listing this key (plus comments/blanks) authorizes the token.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	authorized, err := humangate.ParseAuthorizedKeys([]byte(
		"# owner keys\n\n" + hex.EncodeToString(pub) + "\n" + hex.EncodeToString(otherPub) + "\n"))
	if err != nil {
		t.Fatalf("ParseAuthorizedKeys: %v", err)
	}
	if !inSet(got, authorized) {
		t.Fatal("signer key should be in the authorized set")
	}

	// A set that does not contain it must refuse.
	only, err := humangate.ParseAuthorizedKeys([]byte(hex.EncodeToString(otherPub) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if inSet(got, only) {
		t.Fatal("signer key must NOT match a different authorized set")
	}
}

// COSE-EdDSA extraction: a WebAuthn (fido2) EdDSA token's effective identity is
// its credential public key; an ES256 (P-256) credential cannot be an ed25519
// authority key and SignerKey rejects it rather than passing falsely. Built with
// the in-process fake bridge, so no hardware is needed.
func TestSignerKeyWebAuthn(t *testing.T) {
	fb := startFakeBridge(t)
	rr, err := bridge.NewClient(fb.sock).Do(bridge.Request{
		Op: bridge.OpRegister, RPID: humangate.DefaultRPID, UserName: "humangate", Alg: bridge.AlgEdDSA,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	reg := &humangate.KeyRegistry{}
	reg.Add(humangate.EnrolledKey{
		Label: "test", RPID: humangate.DefaultRPID,
		CredentialID: rr.CredentialID, PubKey: rr.PubKey, Alg: rr.Alg,
	})
	tok, err := humangate.RequireApproval(context.Background(),
		humangate.Request{Action: "invoke", Subject: "claude-code", Methods: []humangate.Method{humangate.MethodFIDO2}},
		humangate.WithApprover(humangate.NewFIDO2Approver(fb.sock, reg)))
	if err != nil {
		t.Fatalf("RequireApproval(fido2): %v", err)
	}
	if tok.WebAuthn == nil {
		t.Fatal("expected a WebAuthn proof on the token")
	}

	got, err := tok.SignerKey()
	if err != nil {
		t.Fatalf("SignerKey(webauthn eddsa): %v", err)
	}
	if !got.Equal(ed25519.PublicKey(rr.PubKey)) {
		t.Fatalf("SignerKey = %x, want credential pub %x", got, rr.PubKey)
	}

	// An ES256 credential: SignerKey must error, mentioning ed25519/EdDSA.
	es := &humangate.ApprovalToken{
		KeyID:    hex.EncodeToString(make([]byte, 65)),
		WebAuthn: &humangate.WebAuthnProof{Alg: bridge.AlgES256, PubKey: make([]byte, 65)},
	}
	if _, err := es.SignerKey(); err == nil {
		t.Fatal("SignerKey must reject an ES256 credential for ed25519 authority matching")
	} else if !strings.Contains(err.Error(), "EdDSA") && !strings.Contains(err.Error(), "ed25519") {
		t.Fatalf("ES256 error should name EdDSA/ed25519, got: %v", err)
	}
}

// The authorized-keys format matches interpose: blank lines and '#'-comments are
// ignored, and a malformed line is a line-numbered error.
func TestParseAuthorizedKeysFormat(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(nil)
	b, _, _ := ed25519.GenerateKey(nil)
	keys, err := humangate.ParseAuthorizedKeys([]byte(
		"# comment\n\n  " + hex.EncodeToString(a) + "  \n" + hex.EncodeToString(b) + "\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 2 || !keys[0].Equal(a) || !keys[1].Equal(b) {
		t.Fatalf("want [a b], got %d keys", len(keys))
	}
	if _, err := humangate.ParseAuthorizedKeys([]byte("not-a-key")); err == nil {
		t.Fatal("expected an error on a malformed line")
	}
}
