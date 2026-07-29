# Changelog

All notable changes to nono-bio-gate. Each released version is retained under
`builds/releases/<version>/`.

## v0.1.0 (unreleased)

First cut. Standalone, silent by default, no dependencies beyond the Go stdlib.

- `biogate.RequireApproval` primitive: run one approval ceremony, return a signed
  ed25519 `ApprovalToken` (who, what, when, key id) or `ErrRefused`.
- `Verify` / `ParseToken` / `Marshal` for portable, self-verifying proof.
- Approvers: `tty` (interactive dev default) and `route` (exec an external
  command, exit code = decision, e.g. route over the interpose CLI).
- Hardware keys (option B): `biogate register` enrolls an external FIDO2 key and
  `--method fido2` makes the key sign each approval (the assertion is the proof,
  `WebAuthn` in the token; verified offline against the enrolled public key,
  Ed25519 + best-effort ES256). The cgo/libfido2 dependency is isolated in a
  separate `biogate-fido-bridge` helper over a Unix socket, so the main binary
  stays pure-Go / static. No Apple entitlement (no Secure Enclave / ES).
  `platform` (Touch ID) is intentionally not offered. Build: `make bridge`.
- Signer: **AAuth** is the CLI default (`github.com/aauth-dev/auth-go`) - every
  token embeds an `aa-agent+jwt` bound to the signing key; `VerifyIdentity`
  checks it. `--signer ed25519` keeps a dependency-free path. This is the dogfood
  seam toward the interpose broker.
- LICENSE: full Apache-2.0 text.
- CLI `biogate`: `start` (silent by default, `--logging on` opt-in, exec on
  approval), `verify`, `version`, and a `release` stub (not implemented).
- nono adapter (`adapters/nono`): `GateLaunch`, plus wrapper / hook wiring notes.
- Go 1.26 (toolchain auto-downloaded). Makefile with local + Docker lifecycle.
- Apache-2.0.
