#!/bin/sh
set -eu
PREFIX=/opt/northstar-codex-sidecar
UNIT=/etc/systemd/system/northstar-codex-sidecar.service
if [ "${1:-}" != "--confirm" ]; then echo 'rollback requires --confirm' >&2; exit 2; fi
systemctl disable --now northstar-codex-sidecar.service 2>/dev/null || true
rm -f "$UNIT"
systemctl daemon-reload
rm -rf "$PREFIX"
# The service account and /var/lib/northstar-codex are deliberately left in
# place: they hold Codex login state and run inputs, which a rollback must not
# destroy. Remove them separately and only after confirming nothing needs them.
echo 'note: service account northstar-codex and /var/lib/northstar-codex were preserved' >&2
printf '%s\n' rolled_back
