# Examples

Runnable examples for nono-bio-gate. Build first: `make build` (produces
`builds/bin/biogate` and the pure-Go `builds/bin/biogate-fido-bridge` stub).

## Do I need the bridge running?

| method | bridge required? |
|---|---|
| `tty`, `route` | no — the main binary does it all |
| `fido2` (hardware key) | **yes** — start `biogate-fido-bridge` first; it owns libfido2/USB |

The bridge and the main binary find each other on a default socket, or pass
`--socket <path>` to both.

## 1. Terminal tap (no setup)

```sh
./builds/bin/biogate start --subject claude-code -- echo "launched"
# prompts: approve launch "claude-code"? [y/N]
```

## 2. Route the decision to your own approver

`route-approver.sh` is a sample command whose **exit code** is the decision
(0 approve, non-zero refuse); the request arrives on env vars / stdin.

```sh
chmod +x examples/route-approver.sh
./builds/bin/biogate start --method route \
  --route "examples/route-approver.sh" --subject claude-code -- echo "launched"
```

## 3. Library usage (Go)

```sh
go run ./examples/library      # gates via route, prints the signed token
```

## 4. Hardware key — the real tap

Needs `libfido2` and a plugged-in FIDO2 key. `hardware-tap.sh` builds the bridge
(`-tags fido2`), starts it, enrolls your key, gates an approval, and verifies it.

```sh
brew install libfido2          # or: apt install libfido2-dev
chmod +x examples/hardware-tap.sh
examples/hardware-tap.sh       # set BIOGATE_PIN=xxxx if your key needs a PIN
```

Or by hand:

```sh
make bridge                                     # build the fido2 bridge
./builds/bin/biogate-fido-bridge &              # run the helper
./builds/bin/biogate register --label my-key    # TOUCH your key to enroll
./builds/bin/biogate start --method fido2 --subject claude-code --out /tmp/a.json
./builds/bin/biogate verify /tmp/a.json         # offline, no device
```

## Make commands used here

| command | what |
|---|---|
| `make build` | build `biogate` + the bridge stub into `builds/bin` (pure-Go) |
| `make bridge` | build `biogate-fido-bridge` **with** libfido2 (`-tags fido2`) |
| `make test` | run the black-box suite in `test/` (no hardware needed) |
| `make run ARGS="start -- echo hi"` | build and run in the foreground |
| `make example-route` | run example 2 above |
| `make example-hardware` | run `examples/hardware-tap.sh` |
| `make docker-build` / `make docker-run ARGS=version` | container build / run |
| `make help` | list every target |
