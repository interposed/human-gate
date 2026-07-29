package biogate

import (
	"context"
	"crypto/ed25519"
	"testing"
)

func TestAAuthSignerMintsAndBindsIdentity(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewAAuthSigner("aauth:biogate@test.local", priv)
	if err != nil {
		t.Fatalf("NewAAuthSigner: %v", err)
	}

	tok, err := RequireApproval(context.Background(),
		Request{Action: "launch", Subject: "claude-code", Methods: []Method{mMock}},
		WithApprover(mockApprover{}), WithSigner(s),
	)
	if err != nil {
		t.Fatalf("RequireApproval: %v", err)
	}
	if tok.Agent == "" {
		t.Fatal("expected an aa-agent+jwt in token.Agent")
	}
	if err := Verify(tok); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, err := VerifyIdentity(context.Background(), tok); err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}

	// tampering must break both the approval signature and identity binding
	bad := *tok
	bad.Subject = "evil"
	if _, err := VerifyIdentity(context.Background(), &bad); err == nil {
		t.Fatal("VerifyIdentity accepted a tampered token")
	}
}
