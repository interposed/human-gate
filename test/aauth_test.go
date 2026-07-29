package biogatetest

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/interposed/nono-biogate/biogate"
)

func TestAAuthSignerIdentity(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	s, err := biogate.NewAAuthSigner("aauth:biogate@test.local", priv)
	if err != nil {
		t.Fatalf("NewAAuthSigner: %v", err)
	}
	tok, err := biogate.RequireApproval(context.Background(), req("mock"),
		biogate.WithApprover(mockApprover{}), biogate.WithSigner(s))
	if err != nil {
		t.Fatal(err)
	}
	if tok.Agent == "" {
		t.Fatal("expected an aa-agent+jwt in token.Agent")
	}
	if err := biogate.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := biogate.VerifyIdentity(context.Background(), tok); err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}
	bad := *tok
	bad.Subject = "evil"
	if _, err := biogate.VerifyIdentity(context.Background(), &bad); err == nil {
		t.Fatal("VerifyIdentity accepted a tampered token")
	}
}
