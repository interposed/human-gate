#!/usr/bin/env bash
#
# End-to-end HARDWARE test: build the bridge, run it, enroll your FIDO2 key, and
# gate an approval with a real tap. Requires libfido2 and a plugged-in key.
#
#   brew install libfido2        # or: apt install libfido2-dev
#   examples/hardware-tap.sh
#
# If your key requires a PIN for resident credentials, set HUMANGATE_PIN=xxxx.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=./builds/bin
SOCK="${TMPDIR:-/tmp}/humangate-fido-bridge.sock"
TOKEN="${TMPDIR:-/tmp}/humangate-approval.json"
PIN_ARGS=()
[ -n "${HUMANGATE_PIN:-}" ] && PIN_ARGS=(--pin "$HUMANGATE_PIN")

echo "==> building humangate + the fido bridge (-tags fido2, needs libfido2)"
make build  >/dev/null
make bridge

echo "==> starting humangate-fido-bridge on $SOCK"
"$BIN/humangate-fido-bridge" --socket "$SOCK" &
BRIDGE_PID=$!
trap 'kill "$BRIDGE_PID" 2>/dev/null || true; rm -f "$SOCK"' EXIT
sleep 0.6

echo
echo "==> STEP 1: enroll your key  (TOUCH it when it blinks)"
"$BIN/humangate" register --label my-key --socket "$SOCK" ${PIN_ARGS[@]+"${PIN_ARGS[@]}"}

echo
echo "==> STEP 2: gate an approval  (TOUCH your key again)"
"$BIN/humangate" start --method fido2 --subject claude-code \
  --socket "$SOCK" --out "$TOKEN" --logging on ${PIN_ARGS[@]+"${PIN_ARGS[@]}"}

echo
echo "==> STEP 3: verify the signed approval (offline, no device)"
"$BIN/humangate" verify "$TOKEN"

echo
echo "==> the signed token:"
cat "$TOKEN"
echo
echo "==> done. enrolled keys: ~/.config/humangate/keys.json"
