// Command humangate is the standalone hardware/biometric approval gate.
//
// It is silent by default: no screens, no output. It runs an approval ceremony
// and, on approval, execs the wrapped command. Logging is opt-in.
//
//	humangate start --logging on -- nono run claude   # gate a launch, log the decision
//	humangate start --method route --route "interpose request approve" -- claude
//	humangate verify approval.json                     # inspect a signed token
//
// The approval token is signed proof (who, what, when, which key) that any
// holder can verify. Nothing phones home; nothing here needs interpose.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/interposed/human-gate/humangate"
	"github.com/interposed/human-gate/humangate/bridge"
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
		fmt.Fprintln(os.Stderr, "humangate release: not implemented")
		os.Exit(3)
	case "version", "--version", "-v":
		fmt.Println("humangate", version)
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
		method   = string(humangate.MethodTTY)
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
			fmt.Fprintln(os.Stderr, "humangate: unknown flag:", flags[i])
			return 2
		}
	}

	// silent by default; logging is opt-in
	var logw io.Writer
	if logging == "on" || logging == "true" {
		if logFile != "" {
			f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				fmt.Fprintln(os.Stderr, "humangate: log file:", err)
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
			fmt.Fprintf(logw, "[humangate] "+format+"\n", a...)
		}
	})

	if subject == "" && len(cmd) > 0 {
		subject = cmd[0]
	}
	if subject == "" {
		fmt.Fprintln(os.Stderr, "humangate: need --subject or a -- command")
		return 2
	}

	key, err := humangate.LoadOrCreateKey(keyPath)
	if err != nil {
		log("key error: %v", err)
		fmt.Fprintln(os.Stderr, "humangate: key:", err)
		return 1
	}
	var signer humangate.Signer
	switch signerID {
	case "aauth", "":
		if identity == "" {
			host, _ := os.Hostname()
			if host == "" {
				host = "local"
			}
			// aauth-go v0.3.0 validateDomain rejects a non-lowercase domain, and a
			// macOS hostname is commonly mixed-case (e.g. Foo-Mac.local), so lowercase
			// the default identity's host rather than fail the ceremony.
			identity = "aauth:humangate@" + strings.ToLower(host)
		}
		signer, err = humangate.NewAAuthSigner(identity, key)
		if err != nil {
			log("aauth signer error: %v", err)
			fmt.Fprintln(os.Stderr, "humangate: aauth:", err)
			return 1
		}
	case "ed25519":
		signer = humangate.NewEd25519Signer(key)
	default:
		fmt.Fprintln(os.Stderr, "humangate: unknown --signer:", signerID)
		return 2
	}

	opts := []humangate.Option{humangate.WithSigner(signer)}
	switch humangate.Method(method) {
	case humangate.MethodRoute:
		if route == "" {
			fmt.Fprintln(os.Stderr, "humangate: --method route needs --route \"cmd args\"")
			return 2
		}
		opts = append(opts, humangate.WithApprover(humangate.NewExecApprover(humangate.MethodRoute, strings.Fields(route)...)))
	case humangate.MethodFIDO2:
		reg, rerr := humangate.LoadRegistry(humangate.DefaultRegistryPath())
		if rerr != nil {
			fmt.Fprintln(os.Stderr, "humangate: registry:", rerr)
			return 1
		}
		opts = append(opts, humangate.WithApprover(humangate.NewFIDO2Approver(sock, reg)))
	case humangate.MethodPlatform:
		opts = append(opts, humangate.WithApprover(humangate.NewPlatformApprover()))
	case humangate.MethodTTY:
		// built-in default approver already registered
	default:
		fmt.Fprintln(os.Stderr, "humangate: unknown method:", method)
		return 2
	}

	req := humangate.Request{
		Action:  action,
		Subject: subject,
		Detail:  detail,
		Methods: []humangate.Method{humangate.Method(method)},
		Timeout: timeout,
	}
	log("approval requested action=%s subject=%q method=%s", action, subject, method)

	tok, err := humangate.RequireApproval(context.Background(), req, opts...)
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
		fmt.Fprintln(os.Stderr, "humangate: exec:", err)
		return 127
	}
	return 0
}

func runVerify(args []string) int {
	var (
		tokenPath string
		authKeys  string
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--authorized-keys":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "humangate verify: --authorized-keys needs a path")
				return 2
			}
			i++
			authKeys = args[i]
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintln(os.Stderr, "humangate verify: unknown flag:", args[i])
				return 2
			}
			if tokenPath != "" {
				fmt.Fprintln(os.Stderr, "usage: humangate verify [--authorized-keys <path>] <token.json>")
				return 2
			}
			tokenPath = args[i]
		}
	}
	if tokenPath == "" {
		fmt.Fprintln(os.Stderr, "usage: humangate verify [--authorized-keys <path>] <token.json>")
		return 2
	}
	b, err := os.ReadFile(tokenPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "humangate:", err)
		return 1
	}
	tok, err := humangate.ParseToken(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "humangate:", err)
		return 1
	}
	if err := humangate.Verify(tok); err != nil {
		fmt.Fprintln(os.Stderr, "INVALID:", err)
		return 1
	}
	// Optional owner-key binding: the signature already verified; now require
	// that the token's effective signing identity is one of the authorized keys.
	if authKeys != "" {
		body, err := os.ReadFile(authKeys)
		if err != nil {
			fmt.Fprintln(os.Stderr, "humangate:", err)
			return 1
		}
		authorized, err := humangate.ParseAuthorizedKeys(body)
		if err != nil {
			fmt.Fprintln(os.Stderr, "humangate:", err)
			return 1
		}
		signer, err := tok.SignerKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, "UNAUTHORIZED:", err)
			return 1
		}
		authorizedOK := false
		for _, a := range authorized {
			if signer.Equal(a) {
				authorizedOK = true
				break
			}
		}
		if !authorizedOK {
			fmt.Fprintln(os.Stderr, "UNAUTHORIZED: approval signing key is not in the authorized set")
			return 1
		}
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
		regPath = humangate.DefaultRegistryPath()
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
			fmt.Fprintln(os.Stderr, "humangate register: unknown flag:", args[i])
			return 2
		}
	}
	alg := bridge.AlgEdDSA
	if algStr == "es256" {
		alg = bridge.AlgES256
	}

	cli := bridge.NewClient(sock)
	if err := cli.Ping(); err != nil {
		fmt.Fprintln(os.Stderr, "humangate register:", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "touch your security key to enroll it...")
	resp, err := cli.Do(bridge.Request{
		Op: bridge.OpRegister, RPID: humangate.DefaultRPID, RPName: "human-gate",
		UserName: "humangate", PIN: pin, Alg: alg,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "humangate register:", err)
		return 1
	}
	reg, err := humangate.LoadRegistry(regPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "humangate register:", err)
		return 1
	}
	reg.Add(humangate.EnrolledKey{
		Label: label, RPID: humangate.DefaultRPID,
		CredentialID: resp.CredentialID, PubKey: resp.PubKey, Alg: resp.Alg,
		AddedAt: time.Now(),
	})
	if err := reg.Save(regPath); err != nil {
		fmt.Fprintln(os.Stderr, "humangate register:", err)
		return 1
	}
	fmt.Printf("enrolled %q (alg %d) -> %s\n", label, resp.Alg, regPath)
	// For an EdDSA credential, print the public key so it can be enrolled as an
	// approval authority (e.g. `interpose agents register-key <hex>`): a governed
	// approval is signed by THIS credential, so a verifier binding to enrolled keys
	// must trust it. (ES256/P-256 keys can't be used that way.)
	if resp.Alg == bridge.AlgEdDSA && len(resp.PubKey) == ed25519.PublicKeySize {
		fmt.Printf("authority key (hex, for register-key): %s\n", hex.EncodeToString(resp.PubKey))
	}
	return 0
}

func defaultKeyPath() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "humangate", "key")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "humangate", "key")
}

func usage(w io.Writer) {
	fmt.Fprint(w, `humangate - a hardware/biometric approval gate. silent by default.

usage:
  humangate start [flags] [-- command args...]
  humangate register [--label <name>] [--alg eddsa|es256] [--pin <pin>] [--socket <path>]
  humangate verify [--authorized-keys <path>] <token.json>
  humangate release            (stub: not implemented)
  humangate version

register enrolls a hardware key via the humangate-fido-bridge helper (option B:
the key signs each approval). start --method fido2 then taps that key.

verify checks the token's signature/assertion offline. With --authorized-keys it
ALSO requires the token's signing key to be one of the hex ed25519 public keys in
that file (one per line, blank lines and '#'-comments ignored); otherwise exits
non-zero with UNAUTHORIZED.

start flags:
  --logging on|off      enable logging (default off; nothing is printed otherwise)
  --log-file <path>     write logs here instead of stderr
  --method tty|route|fido2|platform   approval method (default tty)
  --route "<cmd args>"  with --method route: route the decision to this command
                        (exit 0 approves), e.g. "interpose request approve"
  --action <name>       action label (default launch)
  --subject <name>      what is approved (default: the -- command)
  --detail <text>       human-readable context
  --key <path>          signer key file (default ~/.config/humangate/key)
  --signer aauth|ed25519  proof type (default aauth: mints an AAuth aa-agent+jwt)
  --identity <id>       AAuth agent id (default aauth:humangate@<hostname>)
  --out <path>          write the signed approval token here
  --timeout <dur>       ceremony timeout, e.g. 30s
`)
}
