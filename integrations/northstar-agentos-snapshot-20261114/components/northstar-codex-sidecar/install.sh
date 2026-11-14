#!/bin/sh
set -eu

# Account-management tools live in the sbin directories, which a restricted
# root shell (su -c, cron, some CI images) may not have on PATH.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"
export PATH

PREFIX=${1:-/opt/northstar-codex-sidecar}
UNIT=/etc/systemd/system/northstar-codex-sidecar.service
SERVICE_USER=northstar-codex
SERVICE_GROUP=northstar-codex
STATE_ROOT=/var/lib/northstar-codex
CODEX_HOME_DIR="$STATE_ROOT/codex-home"
WORKSPACE_DIR="$STATE_ROOT/workspace"

case "$PREFIX" in /opt/northstar-codex-sidecar) ;; *) echo 'refusing non-canonical install path' >&2; exit 2;; esac

if [ "$(id -u)" -ne 0 ]; then
  echo 'install.sh must run as root: it creates a system account and state directories' >&2
  exit 2
fi

create_service_group() {
  if command -v getent >/dev/null 2>&1 && getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    return 0
  fi
  if command -v groupadd >/dev/null 2>&1; then
    groupadd --system "$SERVICE_GROUP"
  elif command -v addgroup >/dev/null 2>&1; then
    addgroup --system "$SERVICE_GROUP"
  else
    echo 'no groupadd or addgroup available; create the service group manually' >&2
    exit 3
  fi
}

create_service_user() {
  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    return 0
  fi
  nologin=/bin/false
  for candidate in /usr/sbin/nologin /sbin/nologin; do
    if [ -x "$candidate" ]; then nologin=$candidate; break; fi
  done
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --gid "$SERVICE_GROUP" --home-dir "$STATE_ROOT" --shell "$nologin" "$SERVICE_USER"
  elif command -v adduser >/dev/null 2>&1; then
    adduser --system --ingroup "$SERVICE_GROUP" --home "$STATE_ROOT" --disabled-login \
      --gecos 'Northstar Codex sidecar' --shell "$nologin" "$SERVICE_USER"
  else
    echo 'no useradd or adduser available; create the service account manually' >&2
    exit 3
  fi
}

create_service_group
create_service_user

install -d -m 755 "$PREFIX"
install -m 755 sidecar.py transport.py service.py sidecar_socket.py "$PREFIX/"
install -m 644 northstar-codex-sidecar.service "$UNIT"

# State directories the unit's ReadWritePaths and the sidecar's defaults expect.
# Credentials and run inputs stay in separate directories.
install -d -m 700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_ROOT" "$CODEX_HOME_DIR" "$WORKSPACE_DIR"

systemctl daemon-reload

if ! command -v codex >/dev/null 2>&1; then
  echo 'warning: codex is not on PATH; set Environment=CODEX_BIN in the unit before enabling' >&2
fi

printf '%s\n' installed
