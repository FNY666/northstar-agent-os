#!/bin/sh
# Remote-worker channel canary (T5) - run by an OPERATOR against a real host.
#
# This script is deliberately not executed by this repository's CI: it needs
# an SSH-reachable worker with the sidecar service running. It is the "real
# (non-fake) end-to-end canary" recipe from the T5 transport spec, phase one.
#
#   PHASE 1 (default): reachability + JSON-lines round trip through the SSH
#   forward. Needs no model and no API key (the probe request is rejected
#   by the server before any process is spawned).
#
#   PHASE 2 (NS_REAL=1): also send one valid tiny request, which launches
#   codex on the worker (codex + credentials must exist there).
#
# Usage:
#   NS_WORKER=user@worker-host sh run_remote_canary.sh
#   NS_WORKER=user@worker-host NS_REAL=1 sh run_remote_canary.sh
#
# Exit codes: 0 pass, 1 failure, 2 inconclusive (phase 2 only).
set -eu

WORKER="${NS_WORKER:?set NS_WORKER=user@worker-host}"
STATE_DIR="${NS_LOCAL_SOCK_DIR:-$HOME/.local/state/northstar/canary}"
SOCKET="$STATE_DIR/sidecar.sock"
REMOTE_SOCKET="${NS_REMOTE_SOCKET:-/var/run/northstar-codex/sidecar.sock}"
CONTROL="$STATE_DIR/ssh-control"

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
rm -f "$CONTROL"

cleanup() {
  ssh -S "$CONTROL" -O exit "$WORKER" >/dev/null 2>&1 || true
  rm -f "$CONTROL"
}
trap cleanup EXIT INT TERM

echo "== remote-worker channel canary =="
echo "   worker        : $WORKER"
echo "   local socket  : $SOCKET"
echo "   remote socket : $REMOTE_SOCKET"
echo

echo "-- 0. worker reachability (key-only SSH)"
ssh -o BatchMode=yes -o ConnectTimeout=10 "$WORKER" true
echo "   reachable"

echo "-- 1. start the socket forward (ssh -N -L, control master)"
ssh -f -N -M -S "$CONTROL" \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    -o BatchMode=yes \
    -L "$SOCKET:$REMOTE_SOCKET" "$WORKER"
echo "   forward started"

echo "-- 2. wait for the forwarded socket"
i=0
until [ -S "$SOCKET" ] || [ "$i" -ge 60 ]; do
  i=$((i + 1))
  sleep 0.5
done
if [ ! -S "$SOCKET" ]; then
  echo "FAIL: forwarded socket never appeared (is the worker's sidecar service up?)" >&2
  exit 1
fi
echo "   socket present after ~$((i / 2))s"

echo "-- 3. deterministic probe (no model, no key)"
if ! python3 probe_socket.py --socket "$SOCKET"; then
  echo "FAIL: probe failed" >&2
  exit 1
fi

if [ "${NS_REAL:-0}" = "1" ]; then
  echo
  echo "-- 4. real run over the channel (needs codex + credentials on the worker)"
  rc=0
  python3 probe_socket.py --socket "$SOCKET" --real || rc=$?
  if [ "$rc" -eq 2 ]; then
    echo "INCONCLUSIVE: channel works; the run itself did not succeed (see above)" >&2
    exit 2
  fi
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
else
  echo
  echo "(phase 2 skipped; rerun with NS_REAL=1 to launch a real run on the worker)"
fi

echo
echo "PASS: remote-worker channel canary succeeded"
