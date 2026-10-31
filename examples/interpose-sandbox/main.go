// Command sandbox-gate requires a human approval before launching an
// interpose-sandbox box, then execs the launch command.
//
// human-gate is the aauth-native approval gate. interpose-sandbox is NOT a
// module dependency here: this example only shells out to its CLI after the
// approval succeeds, so the gate stays independent of the thing it gates.
//
// CLI equivalent (the route/exec pattern, a tap gates the launch):
//
//	humangate start --method fido2 -- interpose sandbox start --tier process -- claude
//
// Run it (the demo approver auto-approves; swap for --method fido2 in
// production):
//
//	go run ./examples/interpose-sandbox -- echo "sandbox would launch here"
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/interposed/human-gate/humangate"
)

func main() {
	// Everything after a literal "--" is the launch command to run on approval.
	launch := os.Args[1:]
	if len(launch) > 0 && launch[0] == "--" {
		launch = launch[1:]
	}
	if len(launch) == 0 {
		// Stand-in for a real launch, e.g. `interpose sandbox start -- claude`
		// or `interpose-ci run pipeline.json`.
		launch = []string{"echo", "interpose sandbox start -- <agent>"}
	}

	tok, err := humangate.RequireApproval(context.Background(), humangate.Request{
		Action:  "launch",
		Subject: "interpose-sandbox",
		Detail:  fmt.Sprintf("sandbox launch: %v", launch),
		Methods: []humangate.Method{humangate.MethodRoute},
	}, humangate.WithApprover(humangate.NewExecApprover(humangate.MethodRoute, "true")))
	if err != nil {
		fmt.Fprintln(os.Stderr, "launch refused:", err)
		os.Exit(1)
	}
	if err := humangate.Verify(tok); err != nil {
		panic(err)
	}
	fmt.Printf("approved (key %s) - launching: %v\n", tok.KeyID, launch)

	cmd := exec.Command(launch[0], launch[1:]...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "launch failed:", err)
		os.Exit(1)
	}
}
