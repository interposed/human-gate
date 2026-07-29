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
- Seams for the silent production path: `fido2` and `platform` (Touch ID /
  Windows Hello) return `ErrNotImplemented` for now.
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
