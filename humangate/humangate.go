// Package humangate gets a hardware or biometric approval from a real person and
// returns signed proof of it. One primitive: RequireApproval.
//
// It is deliberately standalone. It needs no account, no network, and nothing
// from interpose. A default terminal approver and an ed25519 signer are built
// in, so `go get` and one call is enough. Richer methods (roaming FIDO2 keys,
// platform biometrics, or routing the decision over an external CLI) plug in
// through the Approver and Signer seams without changing callers.
package humangate

import (
	"context"
	"errors"
	"time"
)

// Method identifies how a human approves.
type Method string

const (
	// MethodTTY is an interactive terminal confirmation. Built in, the default.
	MethodTTY Method = "tty"
	// MethodRoute hands the decision to an external command (e.g. the interpose
	// CLI) via ExecApprover. Optional, opt-in.
	MethodRoute Method = "route"
	// MethodFIDO2 is a roaming hardware key (CTAP2 hmac-secret). Planned seam.
	MethodFIDO2 Method = "fido2"
	// MethodPlatform is Touch ID / Windows Hello via WebAuthn. Planned seam.
	MethodPlatform Method = "platform"
)

// Request describes the action a human is being asked to approve.
type Request struct {
	Action  string        // "launch", "write", "escalate-network", ...
	Subject string        // "claude-code", a path, a URL, ...
	Detail  string        // human-readable context shown at approval time
	Methods []Method      // acceptable methods, preference order; empty = configured default
	Timeout time.Duration // 0 = no timeout
}

// Errors returned by RequireApproval.
var (
	ErrRefused  = errors.New("humangate: approval refused")
	ErrNoMethod = errors.New("humangate: no approval method available for request")
)

// Approver performs one approval ceremony. Backends (terminal, exec/route,
// FIDO2, platform) implement this; RequireApproval selects one from the
// request's acceptable methods.
type Approver interface {
	Method() Method
	// Approve blocks until the human approves (returns nil) or the ceremony is
	// declined or times out (returns ErrRefused, or a wrapped ctx error).
	Approve(ctx context.Context, req Request) error
}

// Signer turns an approved request into portable, verifiable proof.
type Signer interface {
	Sign(req Request, m Method, at time.Time) (*ApprovalToken, error)
	KeyID() string
}

// ProofApprover is an approver whose ceremony IS the proof: the act of approving
// also produces the signed token (a hardware key signing the challenge). When a
// selected approver implements this, RequireApproval uses it and skips the
// separate Signer. The fido2 approver is the canonical example.
type ProofApprover interface {
	Approver
	ApproveAndSign(ctx context.Context, req Request, at time.Time) (*ApprovalToken, error)
}

type config struct {
	approvers map[Method]Approver
	order     []Method
	signer    Signer
	now       func() time.Time
}

// Option configures RequireApproval.
type Option func(*config)

// WithApprover registers an approval method. The last registered method that
// matches a request becomes selectable; registration order sets the default
// preference when a request lists no methods.
func WithApprover(a Approver) Option {
	return func(c *config) {
		if _, seen := c.approvers[a.Method()]; !seen {
			c.order = append(c.order, a.Method())
		}
		c.approvers[a.Method()] = a
	}
}

// WithSigner sets the signer that mints the ApprovalToken. Supply one for a
// stable identity; the default is an ephemeral per-process key.
func WithSigner(s Signer) Option { return func(c *config) { c.signer = s } }

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option { return func(c *config) { c.now = now } }

func defaults() *config {
	s, _ := NewEphemeralSigner()
	c := &config{approvers: map[Method]Approver{}, signer: s, now: time.Now}
	WithApprover(NewTTYApprover())(c)
	return c
}

func (c *config) pick(requested []Method) Approver {
	cand := requested
	if len(cand) == 0 {
		cand = c.order
	}
	for _, m := range cand {
		if a, ok := c.approvers[m]; ok {
			return a
		}
	}
	return nil
}

// RequireApproval runs one approval ceremony and, on approval, returns a signed
// ApprovalToken. It returns ErrRefused if the human declines, ErrNoMethod if no
// configured method satisfies the request.
func RequireApproval(ctx context.Context, req Request, opts ...Option) (*ApprovalToken, error) {
	c := defaults()
	for _, o := range opts {
		o(c)
	}
	a := c.pick(req.Methods)
	if a == nil {
		return nil, ErrNoMethod
	}
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}
	if pa, ok := a.(ProofApprover); ok {
		return pa.ApproveAndSign(ctx, req, c.now())
	}
	if err := a.Approve(ctx, req); err != nil {
		return nil, err
	}
	return c.signer.Sign(req, a.Method(), c.now())
}
