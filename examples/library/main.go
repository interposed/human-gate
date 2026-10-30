// Example: use human-gate as a library. Gate an action with the route method
// (no hardware, no prompt) and print the signed token.
//
//	go run ./examples/library
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/interposed/human-gate/humangate"
)

func main() {
	// Require approval. The "route" approver shells out to `true`, which exits 0
	// and therefore approves; swap it for your own command or another method.
	tok, err := humangate.RequireApproval(context.Background(), humangate.Request{
		Action:  "launch",
		Subject: "claude-code",
		Detail:  "workspace ~/proj",
		Methods: []humangate.Method{humangate.MethodRoute},
	}, humangate.WithApprover(humangate.NewExecApprover(humangate.MethodRoute, "true")))
	if err != nil {
		fmt.Fprintln(os.Stderr, "refused:", err)
		os.Exit(1)
	}

	// The token is signed with the default AAuth signer, so it carries an
	// aa-agent+jwt identity plus a signature. Verify is offline.
	if err := humangate.Verify(tok); err != nil {
		panic(err)
	}
	b, _ := tok.Marshal()
	fmt.Println(string(b))
}
