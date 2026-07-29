package biogate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/interposed/nono-bio-gate/biogate/bridge"
)

// Simulates the hardware path with a software Ed25519 key so the WebAuthn verify
// logic is exercised without a physical key: sign authData||challenge, then
// Verify must accept, and tampering must break it.
func TestWebAuthnProofVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	tok := &ApprovalToken{
		V: 1, Action: "invoke", Subject: "claude-code", Method: MethodFIDO2,
		ApprovedAt: time.Unix(1700000000, 0).UTC(), Nonce: randHex(16),
		KeyID: hex.EncodeToString(pub),
	}
	core, err := tok.challengeCore()
	if err != nil {
		t.Fatal(err)
	}
	ch := sha256.Sum256(core)
	authData := []byte("simulated-authenticator-data")
	sig := ed25519.Sign(priv, append(append([]byte{}, authData...), ch[:]...))
	tok.WebAuthn = &WebAuthnProof{
		CredentialID: []byte{1, 2, 3}, PubKey: pub, Alg: bridge.AlgEdDSA,
		AuthData: authData, ClientHash: ch[:], Sig: sig,
	}

	if err := Verify(tok); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// tampering the approved subject changes the challenge core -> reject
	badSubj := *tok
	badSubj.Subject = "evil"
	if err := Verify(&badSubj); err == nil {
		t.Fatal("accepted a token whose subject was changed after the tap")
	}

	// tampering the signature -> reject
	badSig := *tok
	w := *tok.WebAuthn
	w.Sig = append([]byte{}, sig...)
	w.Sig[0] ^= 0xff
	badSig.WebAuthn = &w
	if err := Verify(&badSig); err == nil {
		t.Fatal("accepted a tampered signature")
	}
}
