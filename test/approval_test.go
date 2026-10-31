package humangatetest

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/interposed/human-gate/humangate"
)

func req(methods ...humangate.Method) humangate.Request {
	return humangate.Request{Action: "launch", Subject: "claude-code", Methods: methods}
}

func TestRouteApproveAndRefuse(t *testing.T) {
	// exit 0 approves
	tok, err := humangate.RequireApproval(context.Background(), req(humangate.MethodRoute),
		humangate.WithApprover(humangate.NewExecApprover(humangate.MethodRoute, "true")))
	if err != nil {
		t.Fatalf("route approve: %v", err)
	}
	if err := humangate.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// non-zero refuses
	if _, err := humangate.RequireApproval(context.Background(), req(humangate.MethodRoute),
		humangate.WithApprover(humangate.NewExecApprover(humangate.MethodRoute, "false"))); err != humangate.ErrRefused {
		t.Fatalf("want ErrRefused, got %v", err)
	}
}

// Regression: a routed approver that writes output and exits 0 must still
// approve (nil *os.File on cmd.Stdout/Stderr previously broke this).
func TestRouteApproverWithOutput(t *testing.T) {
	_, err := humangate.RequireApproval(context.Background(), req(humangate.MethodRoute),
		humangate.WithApprover(humangate.NewExecApprover(humangate.MethodRoute,
			"sh", "-c", "echo out; echo err >&2; exit 0")))
	if err != nil {
		t.Fatalf("route approver with output should approve, got %v", err)
	}
}

func TestEd25519SignVerifyTamper(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok, err := humangate.RequireApproval(context.Background(), req("mock"),
		humangate.WithApprover(mockApprover{}), humangate.WithSigner(humangate.NewEd25519Signer(priv)))
	if err != nil {
		t.Fatal(err)
	}
	if err := humangate.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
	tok.Subject = "evil"
	if humangate.Verify(tok) == nil {
		t.Fatal("verify accepted a tampered token")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok, err := humangate.RequireApproval(context.Background(), req("mock"),
		humangate.WithApprover(mockApprover{}), humangate.WithSigner(humangate.NewEd25519Signer(priv)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := tok.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := humangate.ParseToken(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := humangate.Verify(got); err != nil {
		t.Fatalf("verify after round-trip: %v", err)
	}
}

func TestNoMethod(t *testing.T) {
	if _, err := humangate.RequireApproval(context.Background(), req("nope"),
		humangate.WithApprover(mockApprover{})); err != humangate.ErrNoMethod {
		t.Fatalf("want ErrNoMethod, got %v", err)
	}
}
