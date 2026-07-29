#!/usr/bin/env bash
#
# A sample "route" approver. biogate runs this command and reads its EXIT CODE:
#   0        -> approved
#   non-zero -> refused
#
# The approval request arrives as environment variables (and as JSON on stdin),
# so you can plug in any logic: prompt a human, call an approval API, evaluate a
# policy, forward to the interpose CLI, etc.
#
# Try it:
#   biogate start --method route --route "examples/route-approver.sh" \
#     --subject claude-code -- echo "launched"
#
set -euo pipefail

echo "route-approver: action=${BIOGATE_ACTION:-} subject=${BIOGATE_SUBJECT:-} detail=${BIOGATE_DETAIL:-}" >&2

# --- your decision goes here ---------------------------------------------
# Example policy: approve everything except an action named "destroy".
if [ "${BIOGATE_ACTION:-}" = "destroy" ]; then
  echo "route-approver: refused" >&2
  exit 1
fi
# -------------------------------------------------------------------------

exit 0
