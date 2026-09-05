#!/bin/sh
set -eu
PREFIX=${1:-/opt/northstar-codex-sidecar}
UNIT=/etc/systemd/system/northstar-codex-sidecar.service
case "$PREFIX" in /opt/northstar-codex-sidecar) ;; *) echo 'refusing non-canonical install path' >&2; exit 2;; esac
install -d -m 755 "$PREFIX"
install -m 755 sidecar.py transport.py service.py sidecar_socket.py "$PREFIX/"
install -m 644 northstar-codex-sidecar.service "$UNIT"
systemctl daemon-reload
printf '%s\n' installed