// Command nono-example gates a nono agent launch with human-gate.
//
// human-gate is the standalone, aauth-native HITL approval gate. nono is NOT a
// dependency of human-gate; this example is one consumer of it. There are two
// ways to wire human-gate in front of a nono launch:
//
//  1. Wrapper (works today, needs nothing from nono): gate the launch, then run
//     nono. On the command line: `humangate start -- nono run <agent>`. In Go:
//     GateLaunch below, then exec nono.
//
//  2. Hook (preferred, if nono exposes an approval/event hook): point nono at
//     `humangate start ...` as the approver. human-gate stays silent and signals
//     its decision by exit code (0 approve, non-zero refuse), so it drops into
//     any exec-style hook.
//
// Run it:  go run ./examples/nono
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/interposed/human-gate/humangate"
)

// GateLaunch requires human approval before a nono agent launch and returns the
// signed token. methods picks the acceptable approval methods (e.g. MethodFIDO2
// for a hardware tap, MethodRoute for an external command); opts (WithSigner,
// WithApprover) choose the signer and the concrete approver backend.
func GateLaunch(ctx context.Context, agent string, methods []humangate.Method, opts ...humangate.Option) (*humangate.ApprovalToken, error) {
	return humangate.RequireApproval(ctx, humangate.Request{
		Action:  "launch",
		Subject: agent,
		Detail:  "nono sandbox launch",
		Methods: methods,
	}, opts...)
}

func main() {
	// Demo approver: route the decision to `true`, which exits 0 and approves.
	// In production use []humangate.Method{humangate.MethodFIDO2} with the fido2
	// approver so a real hardware tap gates the launch.
	tok, err := GateLaunch(context.Background(), "claude-code",
		[]humangate.Method{humangate.MethodRoute},
		humangate.WithApprover(humangate.NewExecApprover(humangate.MethodRoute, "true")))
	if err != nil {
		fmt.Fprintln(os.Stderr, "launch refused:", err)
		os.Exit(1)
	}

	// The token carries an aa-agent+jwt identity plus a signature. Verify is
	// offline, so a nono hook can check it without any network or account.
	if err := humangate.Verify(tok); err != nil {
		panic(err)
	}
	fmt.Printf("approved: launch %q (key %s)\n", tok.Subject, tok.KeyID)
	// Here a wrapper would exec the real launch, e.g. `nono run claude-code`.
}
