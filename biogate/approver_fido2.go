package biogate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/interposed/nono-bio-gate/biogate/bridge"
)

// DefaultRPID is the FIDO2 relying-party id bio-gate registers and asserts under.
const DefaultRPID = "biogate.local"

// ErrNotImplemented marks a seam that is designed but not yet built.
var ErrNotImplemented = errors.New("biogate: approval method not implemented yet")

// fido2Approver is the silent hardware path (option B): it asks the fido-bridge
// helper to sign the approval challenge with an enrolled key. The tap IS the
// signature, so it is a ProofApprover. It never touches libfido2 itself; the
// bridge owns that cgo dependency.
type fido2Approver struct {
	client *bridge.Client
	reg    *KeyRegistry
	rpID   string
}

// NewFIDO2Approver returns the hardware-key approver. sock is the bridge socket
// (empty = default); reg holds the enrolled keys (run `biogate register` first).
func NewFIDO2Approver(sock string, reg *KeyRegistry) Approver {
	return &fido2Approver{client: bridge.NewClient(sock), reg: reg, rpID: DefaultRPID}
}

func (a *fido2Approver) Method() Method { return MethodFIDO2 }

// Approve satisfies Approver; the real work is in ApproveAndSign.
func (a *fido2Approver) Approve(ctx context.Context, req Request) error {
	_, err := a.ApproveAndSign(ctx, req, time.Now())
	return err
}

func (a *fido2Approver) ApproveAndSign(ctx context.Context, req Request, at time.Time) (*ApprovalToken, error) {
	if a.reg == nil || len(a.reg.Keys) == 0 {
		return nil, ErrNoKeys
	}
	key := a.reg.Keys[0] // first enrolled key; backups are a follow-up (allow-list)

	tok := &ApprovalToken{
		V:          1,
		Action:     req.Action,
		Subject:    req.Subject,
		Detail:     req.Detail,
		Method:     MethodFIDO2,
		ApprovedAt: at.UTC().Truncate(time.Second),
		KeyID:      hex.EncodeToString(key.PubKey),
		Nonce:      randHex(16),
	}
	core, err := tok.challengeCore()
	if err != nil {
		return nil, err
	}
	challenge := sha256.Sum256(core)

	resp, err := a.client.Do(bridge.Request{
		Op:           bridge.OpAssert,
		RPID:         a.rpID,
		CredentialID: key.CredentialID,
		Challenge:    challenge[:],
	})
	if err != nil {
		return nil, err
	}
	tok.WebAuthn = &WebAuthnProof{
		CredentialID: key.CredentialID,
		PubKey:       key.PubKey,
		Alg:          key.Alg,
		AuthData:     resp.AuthData,
		ClientHash:   challenge[:],
		Sig:          resp.Sig,
	}
	if err := Verify(tok); err != nil {
		return nil, err
	}
	return tok, nil
}

// silentApprover is the platform-biometric seam (Touch ID / Windows Hello). We
// deliberately do NOT implement it: that path needs Secure Enclave / OS
// entitlements we don't have. External FIDO2 keys via the bridge are the silent
// path instead.
type silentApprover struct{ method Method }

// NewPlatformApprover returns the platform-biometric seam. Not implemented by
// design (no Secure Enclave entitlement); use MethodFIDO2 instead.
func NewPlatformApprover() Approver { return &silentApprover{method: MethodPlatform} }

func (s *silentApprover) Method() Method { return s.method }

func (s *silentApprover) Approve(ctx context.Context, req Request) error {
	return ErrNotImplemented
}
