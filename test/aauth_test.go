package humangatetest

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/interposed/human-gate/humangate"
)

func TestAAuthSignerIdentity(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	s, err := humangate.NewAAuthSigner("aauth:humangate@test.local", priv)
	if err != nil {
		t.Fatalf("NewAAuthSigner: %v", err)
	}
	tok, err := humangate.RequireApproval(context.Background(), req("mock"),
		humangate.WithApprover(mockApprover{}), humangate.WithSigner(s))
	if err != nil {
		t.Fatal(err)
	}
	if tok.Agent == "" {
		t.Fatal("expected an aa-agent+jwt in token.Agent")
	}
	if err := humangate.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := humangate.VerifyIdentity(context.Background(), tok); err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}
	bad := *tok
	bad.Subject = "evil"
	if _, err := humangate.VerifyIdentity(context.Background(), &bad); err == nil {
		t.Fatal("VerifyIdentity accepted a tampered token")
	}
}
