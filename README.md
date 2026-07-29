# nono-bio-gate

A small, standalone **hardware / biometric approval gate** for [nono](https://nono.sh)
and any agent runner. It does one thing:

> get a hardware or biometric **yes** from a real person, and hand back a **signed proof** of it.

Silent by default. No account, no network, nothing from interpose required. A
built-in terminal approver and an ed25519 signer mean `go get` and one call is
enough; richer methods (roaming FIDO2 keys, platform biometrics, or routing the
decision over an external CLI) plug in through clean seams.

> It **gates**, it does not **enforce.** bio-gate proves a person approved; the
> sandbox (nono, a container, interpose) provides the isolation.

## Library

```go
import "github.com/interposed/nono-bio-gate/biogate"

tok, err := biogate.RequireApproval(ctx, biogate.Request{
    Action:  "launch",
    Subject: "claude-code",
    Detail:  "workspace ~/proj, network: on",
})
// err == biogate.ErrRefused if declined.
// tok is a signed ApprovalToken (who, what, when, key id); verify anywhere:
biogate.Verify(tok)
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
signer, _ := biogate.NewAAuthSigner("aauth:biogate@host", priv)
tok, _ := biogate.RequireApproval(ctx, req, biogate.WithSigner(signer))
claims, _ := biogate.VerifyIdentity(ctx, tok) // proves AAuth identity + binding
```

`biogate.NewEd25519Signer(priv)` is the dependency-free path if you don't want the
identity layer. This is the dogfood seam: the same AAuth identity the interpose
broker adopts, exercised here first.

## CLI

Silent by default; nothing is printed unless you ask for logs.

```sh
# gate a launch, then run the command on approval
biogate start -- nono run claude

# route the decision over another tool (e.g. the interpose CLI); exit 0 approves
biogate start --method route --route "interpose request approve" -- claude

# turn on logging (off by default)
biogate start --logging on --log-file gate.log -- nono run claude

# write the signed token, and verify one later
biogate start --out approval.json -- nono run claude
biogate verify approval.json
```

## Wiring into nono

Two ways, standalone for **any** nono user:

1. **Wrapper** (works today, needs nothing from nono) — gate the launch, then run
   nono: `biogate start -- nono run <agent>`.
2. **Hook** (preferred, if nono exposes an approval/event hook) — point nono at
   `biogate start ...` as the approver. bio-gate stays silent and signals its
   decision by **exit code** (0 approve, non-zero refuse), so it drops into any
   exec-style hook. Whether nono has such a hook is an open research item.

The `--method route` seam lets a nono setup **notify or route** the decision over
the interpose CLI (or anything), without bio-gate depending on interpose.

## Approval methods

| method | what | status |
|---|---|---|
| `tty` | interactive terminal prompt | built in (dev default; the one non-silent method) |
| `route` | shell out to an external command, exit code = decision | built in |
| `fido2` | roaming hardware key (CTAP2 hmac-secret) | seam, planned |
| `platform` | Touch ID / Windows Hello via WebAuthn | seam, planned |

The `fido2` / `platform` methods are the silent production path; the seams exist
so callers can already select them.

## Build

Requires **Go 1.26** (auto-downloaded via the `go` directive in `go.mod`).

```sh
make build          # -> builds/bin/biogate   (never the repo root)
make test
make release VERSION=v0.1.0   # cross-compiles into builds/releases/v0.1.0/
```

Each release is retained under `builds/releases/<version>/`. Binaries stay local;
`checksums.sha256` is the committed release record.

## Docker

```sh
docker build -t nono-bio-gate .
docker run --rm nono-bio-gate version
```

Built on `aauth` primitives, developed in the open. See `CHANGELOG.md`.
Licensed under Apache-2.0.
