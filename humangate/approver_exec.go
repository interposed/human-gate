package humangate

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
)

// ExecApprover routes the decision to an external command. This is how a nono
// setup can notify or route an approval over another tool (for example the
// interpose CLI) without human-gate taking a dependency on it. The command
// receives the request as JSON on stdin and as HUMANGATE_* environment variables,
// and signals its decision by exit code: 0 approves, non-zero refuses.
//
// The routed command owns its own UI. human-gate itself stays silent.
type ExecApprover struct {
	Name    Method   // method label this approver answers to (usually MethodRoute)
	Command []string // argv, e.g. {"interpose", "request", "approve"}
	Stdout  *os.File // where the routed command's output goes; nil = discard
	Stderr  *os.File // nil = discard
}

// NewExecApprover builds a router that shells out to argv. By default the routed
// command's output is discarded, keeping human-gate silent.
func NewExecApprover(method Method, argv ...string) ExecApprover {
	return ExecApprover{Name: method, Command: argv}
}

func (e ExecApprover) Method() Method {
	if e.Name == "" {
		return MethodRoute
	}
	return e.Name
}

func (e ExecApprover) Approve(ctx context.Context, req Request) error {
	if len(e.Command) == 0 {
		return ErrNoMethod
	}
	cmd := exec.CommandContext(ctx, e.Command[0], e.Command[1:]...)
	payload, _ := json.Marshal(req)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Env = append(os.Environ(),
		"HUMANGATE_ACTION="+req.Action,
		"HUMANGATE_SUBJECT="+req.Subject,
		"HUMANGATE_DETAIL="+req.Detail,
	)
	// Only wire these when non-nil: assigning a nil *os.File to the io.Writer
	// fields would make a non-nil interface over a nil pointer, and os/exec would
	// fail every time the routed command writes output. nil => /dev/null.
	if e.Stdout != nil {
		cmd.Stdout = e.Stdout
	}
	if e.Stderr != nil {
		cmd.Stderr = e.Stderr
	}
	if err := cmd.Run(); err != nil {
		return ErrRefused
	}
	return nil
}
