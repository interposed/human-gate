#!/usr/bin/env bash
#
# A sample "route" approver. humangate runs this command and reads its EXIT CODE:
#   0        -> approved
#   non-zero -> refused
#
# The approval request arrives as environment variables (and as JSON on stdin),
# so you can plug in any logic: prompt a human, call an approval API, evaluate a
# policy, forward to the interpose CLI, etc.
#
# Try it:
#   humangate start --method route --route "examples/route-approver.sh" \
#     --subject claude-code -- echo "launched"
#
set -euo pipefail

echo "route-approver: action=${HUMANGATE_ACTION:-} subject=${HUMANGATE_SUBJECT:-} detail=${HUMANGATE_DETAIL:-}" >&2

# --- your decision goes here ---------------------------------------------
# Example policy: approve everything except an action named "destroy".
if [ "${HUMANGATE_ACTION:-}" = "destroy" ]; then
  echo "route-approver: refused" >&2
  exit 1
fi
# -------------------------------------------------------------------------

exit 0
