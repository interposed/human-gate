// Package nono adapts bio-gate to nono-based setups.
//
// bio-gate is standalone and useful to any nono user, with no interpose account
// required. There are two ways to wire it in:
//
//  1. Wrapper (works today, needs nothing from nono): gate the launch, then run
//     nono. `biogate start -- nono run <agent>`, or GateLaunch below in Go.
//
//  2. Hook (preferred, if nono exposes an approval/event hook): point nono at
//     `biogate start ...` as the approver. bio-gate stays silent and signals its
//     decision by exit code (0 approve, non-zero refuse), so it drops into any
//     exec-style hook. Whether nono has such a hook is an open research item;
//     see brainstorming.md.
package nono

import (
	"context"

	"github.com/interposed/nono-bio-gate/biogate"
)

// GateLaunch requires approval before a nono agent launch and returns the signed
// token. Pass options (WithSigner, WithApprover for route/fido2/platform) to
// choose how the human approves and where the decision is routed.
func GateLaunch(ctx context.Context, agent string, opts ...biogate.Option) (*biogate.ApprovalToken, error) {
	return biogate.RequireApproval(ctx, biogate.Request{
		Action:  "launch",
		Subject: agent,
		Detail:  "nono sandbox launch",
	}, opts...)
}
