package humangate

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

// ttyApprover is an interactive terminal confirmation. It is the dependency-free
// default and is meant for development and headless-adjacent use; the production
// path is a silent hardware or biometric ceremony (see the fido2 / platform
// seams). Because it draws a prompt, it is the one method that is not silent.
type ttyApprover struct {
	in     io.Reader
	prompt io.Writer
}

// NewTTYApprover returns the interactive terminal approver, reading stdin and
// prompting on stderr.
func NewTTYApprover() Approver { return &ttyApprover{in: os.Stdin, prompt: os.Stderr} }

func (t *ttyApprover) Method() Method { return MethodTTY }

func (t *ttyApprover) Approve(ctx context.Context, req Request) error {
	fmt.Fprintf(t.prompt, "approve %s %q", req.Action, req.Subject)
	if req.Detail != "" {
		fmt.Fprintf(t.prompt, " (%s)", req.Detail)
	}
	fmt.Fprint(t.prompt, "? [y/N] ")

	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		line, err := bufio.NewReader(t.in).ReadString('\n')
		ch <- res{line, err}
	}()

	select {
	case <-ctx.Done():
		return ErrRefused
	case r := <-ch:
		if r.err != nil && r.line == "" {
			return ErrRefused
		}
		switch strings.ToLower(strings.TrimSpace(r.line)) {
		case "y", "yes":
			return nil
		default:
			return ErrRefused
		}
	}
}
