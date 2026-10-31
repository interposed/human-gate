package humangatetest

import (
	"context"
	"testing"

	"github.com/interposed/human-gate/humangate"
	"github.com/interposed/human-gate/humangate/bridge"
)

// Exercises the whole hardware path end to end through the public API, against
// an in-process fake bridge that signs assertions with a software Ed25519 key:
// register -> registry -> fido2 approver -> bridge protocol -> WebAuthn token ->
// offline Verify. No device required.
func TestFIDO2EndToEnd(t *testing.T) {
	fb := startFakeBridge(t)

	// enroll (what `humangate register` does)
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

	// approve with the hardware method
	ap := humangate.NewFIDO2Approver(fb.sock, reg)
	tok, err := humangate.RequireApproval(context.Background(),
		humangate.Request{Action: "invoke", Subject: "claude-code", Methods: []humangate.Method{humangate.MethodFIDO2}},
		humangate.WithApprover(ap))
	if err != nil {
		t.Fatalf("RequireApproval(fido2): %v", err)
	}
	if tok.WebAuthn == nil {
		t.Fatal("expected a WebAuthn proof on the token")
	}
	if err := humangate.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// the tap signed THIS approval: changing it must break verification
	bad := *tok
	bad.Subject = "evil"
	if humangate.Verify(&bad) == nil {
		t.Fatal("verify accepted an approval whose subject changed after the tap")
	}
}

func TestFIDO2NoKeyEnrolled(t *testing.T) {
	ap := humangate.NewFIDO2Approver("", &humangate.KeyRegistry{})
	if _, err := humangate.RequireApproval(context.Background(),
		humangate.Request{Action: "launch", Subject: "x", Methods: []humangate.Method{humangate.MethodFIDO2}},
		humangate.WithApprover(ap)); err != humangate.ErrNoKeys {
		t.Fatalf("want ErrNoKeys, got %v", err)
	}
}
