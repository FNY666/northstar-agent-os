#!/bin/sh
set -eu
PREFIX=/opt/northstar-codex-sidecar
UNIT=/etc/systemd/system/northstar-codex-sidecar.service
if [ "${1:-}" != "--confirm" ]; then echo 'rollback requires --confirm' >&2; exit 2; fi
systemctl disable --now northstar-codex-sidecar.service 2>/dev/null || true
rm -f "$UNIT"
systemctl daemon-reload
rm -rf "$PREFIX"
printf '%s\n' rolled_back
