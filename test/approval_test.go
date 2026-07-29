package biogatetest

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/interposed/nono-bio-gate/biogate"
)

func req(methods ...biogate.Method) biogate.Request {
	return biogate.Request{Action: "launch", Subject: "claude-code", Methods: methods}
}

func TestRouteApproveAndRefuse(t *testing.T) {
	// exit 0 approves
	tok, err := biogate.RequireApproval(context.Background(), req(biogate.MethodRoute),
		biogate.WithApprover(biogate.NewExecApprover(biogate.MethodRoute, "true")))
	if err != nil {
		t.Fatalf("route approve: %v", err)
	}
	if err := biogate.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// non-zero refuses
	if _, err := biogate.RequireApproval(context.Background(), req(biogate.MethodRoute),
		biogate.WithApprover(biogate.NewExecApprover(biogate.MethodRoute, "false"))); err != biogate.ErrRefused {
		t.Fatalf("want ErrRefused, got %v", err)
	}
}

// Regression: a routed approver that writes output and exits 0 must still
// approve (nil *os.File on cmd.Stdout/Stderr previously broke this).
func TestRouteApproverWithOutput(t *testing.T) {
	_, err := biogate.RequireApproval(context.Background(), req(biogate.MethodRoute),
		biogate.WithApprover(biogate.NewExecApprover(biogate.MethodRoute,
			"sh", "-c", "echo out; echo err >&2; exit 0")))
	if err != nil {
		t.Fatalf("route approver with output should approve, got %v", err)
	}
}

func TestEd25519SignVerifyTamper(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok, err := biogate.RequireApproval(context.Background(), req("mock"),
		biogate.WithApprover(mockApprover{}), biogate.WithSigner(biogate.NewEd25519Signer(priv)))
	if err != nil {
		t.Fatal(err)
	}
	if err := biogate.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
	tok.Subject = "evil"
	if biogate.Verify(tok) == nil {
		t.Fatal("verify accepted a tampered token")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok, err := biogate.RequireApproval(context.Background(), req("mock"),
		biogate.WithApprover(mockApprover{}), biogate.WithSigner(biogate.NewEd25519Signer(priv)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := tok.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := biogate.ParseToken(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := biogate.Verify(got); err != nil {
		t.Fatalf("verify after round-trip: %v", err)
	}
}

func TestNoMethod(t *testing.T) {
	if _, err := biogate.RequireApproval(context.Background(), req("nope"),
		biogate.WithApprover(mockApprover{})); err != biogate.ErrNoMethod {
		t.Fatalf("want ErrNoMethod, got %v", err)
	}
}
