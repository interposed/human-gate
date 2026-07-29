// Command biogate is the standalone hardware/biometric approval gate.
//
// It is silent by default: no screens, no output. It runs an approval ceremony
// and, on approval, execs the wrapped command. Logging is opt-in.
//
//	biogate start --logging on -- nono run claude   # gate a launch, log the decision
//	biogate start --method route --route "interpose request approve" -- claude
//	biogate verify approval.json                     # inspect a signed token
//
// The approval token is signed proof (who, what, when, which key) that any
// holder can verify. Nothing phones home; nothing here needs interpose.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/interposed/nono-biogate/biogate"
	"github.com/interposed/nono-biogate/biogate/bridge"
)

var version = "v0.1.0" // overridden at release via -ldflags

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch args[0] {
	case "start":
		os.Exit(runStart(args[1:]))
	case "verify":
		os.Exit(runVerify(args[1:]))
	case "register":
		os.Exit(runRegister(args[1:]))
	case "release":
		// stub: reserved, no functional task yet
		fmt.Fprintln(os.Stderr, "biogate release: not implemented")
		os.Exit(3)
	case "version", "--version", "-v":
		fmt.Println("biogate", version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		usage(os.Stderr)
		os.Exit(2)
	}
}

// splitDoubleDash returns the args before "--" and the command after it.
func splitDoubleDash(args []string) (before, cmd []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

type logf func(format string, a ...any)

func runStart(args []string) int {
	flags, cmd := splitDoubleDash(args)

	var (
		logging = "off"
		logFile string
		method   = string(biogate.MethodTTY)
		route    string
		action   = "launch"
		subject  string
		detail   string
		keyPath  = defaultKeyPath()
		outPath  string
		timeout  time.Duration
		signerID = "aauth" // aauth | ed25519
		identity string
		sock     string // fido bridge socket (empty = default)
	)
	// tiny hand-rolled flag parse so "--logging on" reads naturally
	for i := 0; i < len(flags); i++ {
		next := func() string {
			if i+1 < len(flags) {
				i++
				return flags[i]
			}
			return ""
		}
		switch flags[i] {
		case "--logging":
			logging = next()
		case "--log-file":
			logFile = next()
		case "--method":
			method = next()
		case "--route":
			route = next()
		case "--action":
			action = next()
		case "--subject":
			subject = next()
		case "--detail":
			detail = next()
		case "--key":
			keyPath = next()
		case "--signer":
			signerID = next()
		case "--identity":
			identity = next()
		case "--socket":
			sock = next()
		case "--out":
			outPath = next()
		case "--timeout":
			if d, err := time.ParseDuration(next()); err == nil {
				timeout = d
			}
		default:
			fmt.Fprintln(os.Stderr, "biogate: unknown flag:", flags[i])
			return 2
		}
	}

	// silent by default; logging is opt-in
	var logw io.Writer
	if logging == "on" || logging == "true" {
		if logFile != "" {
			f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				fmt.Fprintln(os.Stderr, "biogate: log file:", err)
				return 1
			}
			defer f.Close()
			logw = f
		} else {
			logw = os.Stderr
		}
	}
	log := logf(func(format string, a ...any) {
		if logw != nil {
			fmt.Fprintf(logw, "[biogate] "+format+"\n", a...)
		}
	})

	if subject == "" && len(cmd) > 0 {
		subject = cmd[0]
	}
	if subject == "" {
		fmt.Fprintln(os.Stderr, "biogate: need --subject or a -- command")
		return 2
	}

	key, err := biogate.LoadOrCreateKey(keyPath)
	if err != nil {
		log("key error: %v", err)
		fmt.Fprintln(os.Stderr, "biogate: key:", err)
		return 1
	}
	var signer biogate.Signer
	switch signerID {
	case "aauth", "":
		if identity == "" {
			host, _ := os.Hostname()
			if host == "" {
				host = "local"
			}
			identity = "aauth:biogate@" + host
		}
		signer, err = biogate.NewAAuthSigner(identity, key)
		if err != nil {
			log("aauth signer error: %v", err)
			fmt.Fprintln(os.Stderr, "biogate: aauth:", err)
			return 1
		}
	case "ed25519":
		signer = biogate.NewEd25519Signer(key)
	default:
		fmt.Fprintln(os.Stderr, "biogate: unknown --signer:", signerID)
		return 2
	}

	opts := []biogate.Option{biogate.WithSigner(signer)}
	switch biogate.Method(method) {
	case biogate.MethodRoute:
		if route == "" {
			fmt.Fprintln(os.Stderr, "biogate: --method route needs --route \"cmd args\"")
			return 2
		}
		opts = append(opts, biogate.WithApprover(biogate.NewExecApprover(biogate.MethodRoute, strings.Fields(route)...)))
	case biogate.MethodFIDO2:
		reg, rerr := biogate.LoadRegistry(biogate.DefaultRegistryPath())
		if rerr != nil {
			fmt.Fprintln(os.Stderr, "biogate: registry:", rerr)
			return 1
		}
		opts = append(opts, biogate.WithApprover(biogate.NewFIDO2Approver(sock, reg)))
	case biogate.MethodPlatform:
		opts = append(opts, biogate.WithApprover(biogate.NewPlatformApprover()))
	case biogate.MethodTTY:
		// built-in default approver already registered
	default:
		fmt.Fprintln(os.Stderr, "biogate: unknown method:", method)
		return 2
	}

	req := biogate.Request{
		Action:  action,
		Subject: subject,
		Detail:  detail,
		Methods: []biogate.Method{biogate.Method(method)},
		Timeout: timeout,
	}
	log("approval requested action=%s subject=%q method=%s", action, subject, method)

	tok, err := biogate.RequireApproval(context.Background(), req, opts...)
	if err != nil {
		log("refused: %v", err)
		return 1
	}
	log("approved key=%s method=%s at=%s", tok.KeyID[:16], tok.Method, tok.ApprovedAt.Format(time.RFC3339))

	if outPath != "" {
		b, _ := tok.Marshal()
		if err := os.WriteFile(outPath, b, 0o600); err != nil {
			log("token write error: %v", err)
		}
	}

	if len(cmd) == 0 {
		return 0 // gate-only: approval succeeded, nothing to launch
	}
	log("exec %v", cmd)
	return execCommand(cmd)
}

func execCommand(cmd []string) int {
	c := exec.Command(cmd[0], cmd[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "biogate: exec:", err)
		return 127
	}
	return 0
}

func runVerify(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: biogate verify <token.json>")
		return 2
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "biogate:", err)
		return 1
	}
	tok, err := biogate.ParseToken(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "biogate:", err)
		return 1
	}
	if err := biogate.Verify(tok); err != nil {
		fmt.Fprintln(os.Stderr, "INVALID:", err)
		return 1
	}
	fmt.Printf("OK  %s %q  method=%s  at=%s  key=%s\n",
		tok.Action, tok.Subject, tok.Method, tok.ApprovedAt.Format(time.RFC3339), tok.KeyID[:16])
	return 0
}

func runRegister(args []string) int {
	var (
		sock    string
		label   = "key-1"
		pin     string
		algStr  = "eddsa"
		regPath = biogate.DefaultRegistryPath()
	)
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "--socket":
			sock = next()
		case "--label":
			label = next()
		case "--pin":
			pin = next()
		case "--alg":
			algStr = next()
		case "--registry":
			regPath = next()
		default:
			fmt.Fprintln(os.Stderr, "biogate register: unknown flag:", args[i])
			return 2
		}
	}
	alg := bridge.AlgEdDSA
	if algStr == "es256" {
		alg = bridge.AlgES256
	}

	cli := bridge.NewClient(sock)
	if err := cli.Ping(); err != nil {
		fmt.Fprintln(os.Stderr, "biogate register:", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "touch your security key to enroll it...")
	resp, err := cli.Do(bridge.Request{
		Op: bridge.OpRegister, RPID: biogate.DefaultRPID, RPName: "nono-bio-gate",
		UserName: "biogate", PIN: pin, Alg: alg,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "biogate register:", err)
		return 1
	}
	reg, err := biogate.LoadRegistry(regPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "biogate register:", err)
		return 1
	}
	reg.Add(biogate.EnrolledKey{
		Label: label, RPID: biogate.DefaultRPID,
		CredentialID: resp.CredentialID, PubKey: resp.PubKey, Alg: resp.Alg,
		AddedAt: time.Now(),
	})
	if err := reg.Save(regPath); err != nil {
		fmt.Fprintln(os.Stderr, "biogate register:", err)
		return 1
	}
	fmt.Printf("enrolled %q (alg %d) -> %s\n", label, resp.Alg, regPath)
	return 0
}

func defaultKeyPath() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "biogate", "key")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "biogate", "key")
}

func usage(w io.Writer) {
	fmt.Fprint(w, `biogate - a hardware/biometric approval gate. silent by default.

usage:
  biogate start [flags] [-- command args...]
  biogate register [--label <name>] [--alg eddsa|es256] [--pin <pin>] [--socket <path>]
  biogate verify <token.json>
  biogate release            (stub: not implemented)
  biogate version

register enrolls a hardware key via the biogate-fido-bridge helper (option B:
the key signs each approval). start --method fido2 then taps that key.

start flags:
  --logging on|off      enable logging (default off; nothing is printed otherwise)
  --log-file <path>     write logs here instead of stderr
  --method tty|route|fido2|platform   approval method (default tty)
  --route "<cmd args>"  with --method route: route the decision to this command
                        (exit 0 approves), e.g. "interpose request approve"
  --action <name>       action label (default launch)
  --subject <name>      what is approved (default: the -- command)
  --detail <text>       human-readable context
  --key <path>          signer key file (default ~/.config/biogate/key)
  --signer aauth|ed25519  proof type (default aauth: mints an AAuth aa-agent+jwt)
  --identity <id>       AAuth agent id (default aauth:biogate@<hostname>)
  --out <path>          write the signed approval token here
  --timeout <dur>       ceremony timeout, e.g. 30s
`)
}
