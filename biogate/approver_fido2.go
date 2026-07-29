package biogate

import (
	"context"
	"errors"
)

// ErrNotImplemented marks a seam that is designed but not yet built.
var ErrNotImplemented = errors.New("biogate: approval method not implemented yet")

// silentApprover is the production shape: a hardware key tap or a platform
// biometric (Touch ID, Windows Hello) that shows no screen of its own. It is the
// intended default for real deployments, where the whole point is a silent
// "human present" gate rather than a terminal prompt.
//
// Not implemented yet. The seam exists so callers and the CLI can already select
// MethodFIDO2 / MethodPlatform and pick these up unchanged once the WebAuthn /
// CTAP2 backends land.
type silentApprover struct{ method Method }

// NewFIDO2Approver returns the roaming-hardware-key approver seam (CTAP2
// hmac-secret). Planned; currently returns ErrNotImplemented on use.
func NewFIDO2Approver() Approver { return &silentApprover{method: MethodFIDO2} }

// NewPlatformApprover returns the platform-biometric approver seam (Touch ID /
// Windows Hello via WebAuthn). Planned; currently returns ErrNotImplemented.
func NewPlatformApprover() Approver { return &silentApprover{method: MethodPlatform} }

func (s *silentApprover) Method() Method { return s.method }

func (s *silentApprover) Approve(ctx context.Context, req Request) error {
	return ErrNotImplemented
}
