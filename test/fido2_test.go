package biogatetest

import (
	"context"
	"testing"

	"github.com/interposed/nono-biogate/biogate"
	"github.com/interposed/nono-biogate/biogate/bridge"
)

// Exercises the whole hardware path end to end through the public API, against
// an in-process fake bridge that signs assertions with a software Ed25519 key:
// register -> registry -> fido2 approver -> bridge protocol -> WebAuthn token ->
// offline Verify. No device required.
func TestFIDO2EndToEnd(t *testing.T) {
	fb := startFakeBridge(t)

	// enroll (what `biogate register` does)
	rr, err := bridge.NewClient(fb.sock).Do(bridge.Request{
		Op: bridge.OpRegister, RPID: biogate.DefaultRPID, UserName: "biogate", Alg: bridge.AlgEdDSA,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	reg := &biogate.KeyRegistry{}
	reg.Add(biogate.EnrolledKey{
		Label: "test", RPID: biogate.DefaultRPID,
		CredentialID: rr.CredentialID, PubKey: rr.PubKey, Alg: rr.Alg,
	})

	// approve with the hardware method
	ap := biogate.NewFIDO2Approver(fb.sock, reg)
	tok, err := biogate.RequireApproval(context.Background(),
		biogate.Request{Action: "invoke", Subject: "claude-code", Methods: []biogate.Method{biogate.MethodFIDO2}},
		biogate.WithApprover(ap))
	if err != nil {
		t.Fatalf("RequireApproval(fido2): %v", err)
	}
	if tok.WebAuthn == nil {
		t.Fatal("expected a WebAuthn proof on the token")
	}
	if err := biogate.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// the tap signed THIS approval: changing it must break verification
	bad := *tok
	bad.Subject = "evil"
	if biogate.Verify(&bad) == nil {
		t.Fatal("verify accepted an approval whose subject changed after the tap")
	}
}

func TestFIDO2NoKeyEnrolled(t *testing.T) {
	ap := biogate.NewFIDO2Approver("", &biogate.KeyRegistry{})
	if _, err := biogate.RequireApproval(context.Background(),
		biogate.Request{Action: "launch", Subject: "x", Methods: []biogate.Method{biogate.MethodFIDO2}},
		biogate.WithApprover(ap)); err != biogate.ErrNoKeys {
		t.Fatalf("want ErrNoKeys, got %v", err)
	}
}
