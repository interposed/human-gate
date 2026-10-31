# human-gate

[![govulncheck](https://github.com/interposed/human-gate/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/interposed/human-gate/actions/workflows/govulncheck.yml)

A small, standalone **hardware / biometric approval gate** for any agent runner,
sandbox, or CLI. It does one thing:

> get a hardware or biometric **yes** from a real person, and hand back a **signed proof** of it.

Silent by default. No account, no network, nothing from interpose required. A
built-in terminal approver and an ed25519 signer mean `go get` and one call is
enough; richer methods (roaming FIDO2 keys, platform biometrics, or routing the
decision over an external CLI) plug in through clean seams.

> It **gates**, it does not **enforce.** human-gate proves a person approved; the
> sandbox (interpose, a container, nono, your own runner) provides the isolation.

## Library

```go
import "github.com/interposed/human-gate/humangate"

tok, err := humangate.RequireApproval(ctx, humangate.Request{
    Action:  "launch",
    Subject: "claude-code",
    Detail:  "workspace ~/proj, network: on",
})
// err == humangate.ErrRefused if declined.
// tok is a signed ApprovalToken (who, what, when, key id); verify anywhere:
humangate.Verify(tok)
```

The `ApprovalToken` is self-describing: `KeyID` is the public key, so any holder
can check the signature. Whether to *trust* that key is a separate, caller-side
decision.

## Proof & identity

By default the CLI signs with **AAuth** ([`github.com/aauth-dev/auth-go`](https://github.com/aauth-dev/auth-go)):
every token carries an `aa-agent+jwt` that binds the signing key to an agent
identity, alongside a detached signature over the approval payload, both under one
Ed25519 key.

```go
signer, _ := humangate.NewAAuthSigner("aauth:humangate@host", priv)
tok, _ := humangate.RequireApproval(ctx, req, humangate.WithSigner(signer))
claims, _ := humangate.VerifyIdentity(ctx, tok) // proves AAuth identity + binding
```

`humangate.NewEd25519Signer(priv)` is the dependency-free path if you don't want the
identity layer. This is the dogfood seam: the same AAuth identity the interpose
broker adopts, exercised here first.

## CLI

Silent by default; nothing is printed unless you ask for logs.

```sh
# gate a launch, then run the command on approval
humangate start -- claude --dangerously-skip-permissions

# route the decision over another tool (e.g. the interpose CLI); exit 0 approves
humangate start --method route --route "interpose request approve" -- claude

# turn on logging (off by default)
humangate start --logging on --log-file gate.log -- docker run --rm my-agent

# write the signed token, and verify one later
humangate start --out approval.json -- nono run claude
humangate verify approval.json

# verify AND require the signer to be an enrolled key (bind approval to identity)
humangate verify --authorized-keys keys.hex approval.json
```

`--authorized-keys` takes a file of hex ed25519 public keys (one per line); the
token is accepted only if its signer is one of them. This is how a verifier (for
example an interpose box) binds an approval to a specific enrolled person rather
than trusting any self-describing key.

## Wiring into a runner

Two ways, standalone for **any** runner (interpose-sandbox, a container, nono,
your own launcher):

1. **Wrapper** (works today, needs nothing from the runner) - gate the launch,
   then exec it: `humangate start -- <runner> <agent>`.
2. **Hook** (preferred, if the runner exposes an approval/event hook) - point the
   runner at `humangate start ...` as the approver. human-gate stays silent and
   signals its decision by **exit code** (0 approve, non-zero refuse), so it drops
   into any exec-style hook.

The `--method route` seam lets a setup **notify or route** the decision over
another CLI (for example the interpose CLI), without human-gate depending on it.

See `examples/` for runnable wiring: `examples/interpose-sandbox/`,
`examples/nono/`, and the dependency-free `examples/library/`.

## Approval methods

| method | what | status |
|---|---|---|
| `tty` | interactive terminal prompt | built in (dev default; the one non-silent method) |
| `route` | shell out to an external command, exit code = decision | built in |
| `fido2` | external hardware key via the bridge, option B: the key signs the approval | works (needs `make bridge` + libfido2 + `humangate register`) |
| `platform` | Touch ID / Windows Hello | not offered (needs a Secure Enclave entitlement we don't have) |

## Hardware keys (option B)

The cgo `libfido2` dependency is isolated in a **separate helper**,
`humangate-fido-bridge`, so the main binary stays pure-Go / static / Docker-safe.
The main binary talks to the bridge over a Unix socket; the bridge talks raw
CTAP2 to an external FIDO2 key over USB. **No Apple entitlement** (no Secure
Enclave, no Endpoint Security).

```sh
brew install libfido2                 # or: apt install libfido2-dev
make bridge                           # builds humangate-fido-bridge with -tags fido2
./builds/bin/humangate-fido-bridge &    # run the helper
humangate register --label yubikey      # one-time: touch your key to enroll it
humangate start --method fido2 -- nono run claude   # each launch: a silent tap
```

`humangate register` prints the enrolled key's public half as hex, so a verifier
can admit it (for example `interpose agents register-key <hex>` on an interpose
box, or an `--authorized-keys` file).

On approval the key signs `hash(approval)`; the assertion **is** the proof
(`WebAuthn` in the token, `KeyID` = the credential's public key). `humangate verify`
checks it offline against the enrolled public key. Ed25519 credentials are the
primary path; ES256 is supported best-effort.

## Examples

Runnable examples live under `examples/`:

| path | what |
|---|---|
| `examples/library/` | the smallest Go program: ask for approval, get a signed token |
| `examples/nono/` | gate a [nono](https://nono.sh) launch (wrapper + hook) |
| `examples/interpose-sandbox/` | gate an [interpose-sandbox](https://github.com/interposed/interpose-sandbox) launch; human-gate does not depend on it |
| `examples/hardware-tap.sh` | end-to-end FIDO2 tap: build the bridge, enroll, approve, verify |
| `examples/route-approver.sh` | the `--method route` seam: decide via an external command |

## Build

Requires **Go 1.26** (auto-downloaded via the `go` directive in `go.mod`).

```sh
make build          # -> builds/bin/humangate   (never the repo root)
make test
make release VERSION=v0.1.0   # cross-compiles into builds/releases/v0.1.0/
```

Each release is retained under `builds/releases/<version>/`. Binaries stay local;
`checksums.sha256` is the committed release record.

## Docker

```sh
docker build -t human-gate .
docker run --rm human-gate version
```

Built on `aauth` primitives, developed in the open. See `CHANGELOG.md`.
Licensed under Apache-2.0.
