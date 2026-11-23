"""Integration hub (thirtieth batch).

Operational interface for *OAuth-style third-party app integrations* —
connecting external apps, syncing records, and receiving webhooks. The
design vocabulary is informed by the OAuth 2.0 authorization-code flow
(scopes, tokens, consent) and by platform integration hubs (marketplace
apps, per-account connections, sync cursors, signed webhook delivery).

Record semantics:

* :meth:`IntegrationHub.register_app` pins an app (``app-N`` id) with a
  pinned scope vocabulary. Registration is append-only.
* :meth:`IntegrationHub.connect` mints a per-account connection
  (``conn-N`` id). Tokens are **host-reported handles booked by digest
  only** — raw tokens never enter a record, the audit trail, or an
  error. ``connect`` is a pure booking of a completed authorization.
* :meth:`IntegrationHub.disconnect` terminally revokes one connection
  id; a revoked connection never syncs again (fail-closed). A fresh
  connection is a new id.
* :meth:`IntegrationHub.sync` books one host-reported sync run
  (``sync-N`` id) against a *connected* connection: payloads are
  host-reported record *digests* only (never raw data), and the
  connection's sync cursor advances monotonically. Counters are data.
* :meth:`IntegrationHub.webhook` books one inbound webhook receipt
  (``wh-N`` id) for a registered app: the event type is drawn from a
  pinned vocabulary, signature verification is a host-reported boolean
  booked as data. Replayed ids are refused.

House rules: no wall-clock (callers inject non-negative int ``seq``),
frozen dataclasses, fail-closed checks, stdlib-only, records sealed
with a sha256 ``record_digest`` over the canonical payload. State
transitions emit ``audit.ndjson/1`` events; the audit boundary carries
ids and digests only — tokens, secrets, and payload content never
cross it.

Honest boundary: this module books *reported* integration state
consistently (digests recompute, revocation is terminal, replay is
refused). It cannot perform the OAuth wire flow, verify a signature
cryptographically, reach a network, or prove that a sync run actually
transferred data. Production needs a real OAuth client, a secret
manager for tokens, and the app vendor's webhook verifier.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any, Mapping


#: Version pin for this module's record shape.
INTEGRATION_HUB_VERSION = "integration-hub.v1"

#: Schema pin carried by records and audit events.
INTEGRATION_HUB_SCHEMA = "northstar.integration-hub.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Connection statuses.
STATUS_CONNECTED = "connected"
STATUS_DISCONNECTED = "disconnected"
_STATUS = (STATUS_CONNECTED, STATUS_DISCONNECTED)

#: Sync outcomes.
SYNC_OK = "ok"
SYNC_PARTIAL = "partial"
_SYNC_OUTCOMES = (SYNC_OK, SYNC_PARTIAL)

#: Pinned app vocabulary. Each app pins the scopes it may request.
APP_GITHUB = "github"
APP_SLACK = "slack"
APP_GOOGLE_WORKSPACE = "google-workspace"
APP_SALESFORCE = "salesforce"
APP_JIRA = "jira"
APP_NOTION = "notion"
APP_REGISTRY = {
    APP_GITHUB: ("read:org", "read:user", "repo"),
    APP_SLACK: ("chat:write", "channels:read"),
    APP_GOOGLE_WORKSPACE: ("drive.readonly", "calendar.readonly"),
    APP_SALESFORCE: ("api", "refresh_token"),
    APP_JIRA: ("read:jira-work", "write:jira-work"),
    APP_NOTION: ("read:pages", "write:pages"),
}

#: Pinned webhook event-type vocabulary.
WEBHOOK_CONNECTED = "integration.connected"
WEBHOOK_SYNC_STARTED = "integration.sync_started"
WEBHOOK_SYNC_COMPLETED = "integration.sync_completed"
WEBHOOK_SYNC_FAILED = "integration.sync_failed"
WEBHOOK_TOKEN_REFRESHED = "integration.token_refreshed"
WEBHOOK_DISCONNECTED = "integration.disconnected"
WEBHOOK_EVENT_TYPES = (
    WEBHOOK_CONNECTED,
    WEBHOOK_SYNC_STARTED,
    WEBHOOK_SYNC_COMPLETED,
    WEBHOOK_SYNC_FAILED,
    WEBHOOK_TOKEN_REFRESHED,
    WEBHOOK_DISCONNECTED,
)

#: Audit event kinds.
KIND_APP_REGISTERED = "app.registered"
KIND_CONNECTED = "connection.connected"
KIND_DISCONNECTED = "connection.disconnected"
KIND_SYNCED = "connection.synced"
KIND_WEBHOOK = "webhook.received"
KIND_AUDIT = "hub.audit"
_KINDS = (
    KIND_APP_REGISTERED,
    KIND_CONNECTED,
    KIND_DISCONNECTED,
    KIND_SYNCED,
    KIND_WEBHOOK,
    KIND_AUDIT,
)

#: Digest prefix used throughout the module.
_PIN = "sha256:"

_GENESIS = "genesis"


class IntegrationHubError(ValueError):
    """A malformed request or a refused state transition.

    Raised for structural problems (empty ids, unknown app, unknown
    event type, empty digests, bad seq) and for transitions the ledger
    cannot take (connect on an unknown app, sync on a disconnected
    connection, duplicate active connection, replayed webhook).
    *Checks* that only read state (``connection()``, ``app()``,
    ``status()``) never raise for *unknown ids* — they return ``None``;
    malformed argument *types* still raise.
    """


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise IntegrationHubError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IntegrationHubError(f"{field_name} must be a non-empty string")
    return value


def _check_digest(value: Any, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(_PIN)
        or len(value) != len(_PIN) + 64
    ):
        raise IntegrationHubError(
            f"{field_name} must be a 'sha256:'+64hex digest pin"
        )
    try:
        int(value[len(_PIN):], 16)
    except ValueError:
        raise IntegrationHubError(
            f"{field_name} must be a 'sha256:'+64hex digest pin"
        )
    return value


def _check_app_id(value: Any) -> str:
    if value not in APP_REGISTRY:
        raise IntegrationHubError(
            f"app_id must be one of {sorted(APP_REGISTRY)}, saw {value!r}"
        )
    return value


def _check_scopes(app_id: str, scopes: Any) -> tuple:
    if not isinstance(scopes, (tuple, list)):
        raise IntegrationHubError("scopes must be a tuple/list of strings")
    allowed = APP_REGISTRY[app_id]
    seen: set[str] = set()
    for scope in scopes:
        if not isinstance(scope, str) or scope not in allowed:
            raise IntegrationHubError(
                f"scope {scope!r} not in pinned vocabulary for {app_id!r}"
            )
        if scope in seen:
            raise IntegrationHubError(f"duplicate scope {scope!r}")
        seen.add(scope)
    return tuple(scopes)


def _check_event_type(value: Any) -> str:
    if value not in WEBHOOK_EVENT_TYPES:
        raise IntegrationHubError(
            f"event_type must be one of {WEBHOOK_EVENT_TYPES}, saw {value!r}"
        )
    return value


# ---------------------------------------------------------------------------
# Records — append-only ledger, terminal revocation / single delivery
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AppRecord:
    """A pinned integration app.

    ``app_uid`` is the ``app-N`` mint id; ``app_id`` is the pinned
    app vocabulary value. ``scopes`` is the pinned scope subset this
    registration may request.
    """

    app_uid: str
    app_id: str
    scopes: tuple
    seq: int
    record_digest: str = ""


@dataclass(frozen=True)
class ConnectionRecord:
    """One per-account app connection.

    ``status`` is ``connected`` until :meth:`IntegrationHub.disconnect`
    flips it to ``disconnected`` (terminal). ``token_digest`` pins the
    host-reported token *handle* — the raw token is never stored.
    ``last_sync_seq`` is the monotonic sync cursor (``-1`` before the
    first sync run).
    """

    connection_id: str
    app_uid: str
    account_id: str
    status: str
    scopes: tuple
    token_digest: str
    connected_seq: int
    seq: int
    prev_digest: str = _GENESIS
    record_digest: str = ""
    last_sync_seq: int = -1


@dataclass(frozen=True)
class SyncReport:
    """One booked sync run against a connection.

    ``outcome`` is ``ok``/``partial``; counters are host-reported data.
    ``cursor`` is the run's sequence position and must advance
    monotonically per connection. Record *payloads* are host-reported
    digests only (``record_digests``); raw data never enters.
    """

    sync_id: str
    connection_id: str
    outcome: str
    records_created: int
    records_updated: int
    records_deleted: int
    cursor: int
    record_digests: tuple
    seq: int
    record_digest: str = ""


@dataclass(frozen=True)
class WebhookEvent:
    """One booked inbound webhook receipt.

    ``signature_ok`` is host-reported (the module does not verify
    cryptographically — it books the host's verdict). Replayed
    ``event_id`` values are refused fail-closed.
    """

    webhook_id: str
    app_uid: str
    event_id: str
    event_type: str
    signature_ok: bool
    payload_digest: str
    seq: int
    record_digest: str = ""


# ---------------------------------------------------------------------------
# Digest machinery
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest_of(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(dict(payload))).hexdigest()


def _record_payload(kind: str, fields: Mapping[str, Any]) -> dict[str, Any]:
    payload = {
        "schema": INTEGRATION_HUB_SCHEMA,
        "kind": kind,
        **fields,
    }
    return payload


def _sealed(payload: Mapping[str, Any]) -> str:
    return _digest_of(payload)


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def integration_hub_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the integration hub."""
    if kind not in _KINDS:
        raise IntegrationHubError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    for banned in ("token", "secret", "payload", "account"):
        if banned in detail:
            raise IntegrationHubError(
                f"audit detail must not carry {banned!r}"
            )
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "integration_hub",
        "module_version": INTEGRATION_HUB_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# IntegrationHub
# ---------------------------------------------------------------------------


class IntegrationHub:
    """Integration-hub ledger: apps, connections, sync runs, webhooks.

    Append-only per connection chain; disconnect is terminal per
    connection id; webhook ``event_id`` values are single-delivery.
    Mutation seqs must be strictly increasing (fail-closed ledger
    position: failed mutations consume their seq). Thread-safe via an
    RLock. No wall-clock anywhere.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._last_seq = -1
        self._app_counter = 0
        self._conn_counter = 0
        self._sync_counter = 0
        self._wh_counter = 0
        self._apps: dict[str, AppRecord] = {}
        self._connections: dict[str, ConnectionRecord] = {}
        self._active_by_key: dict[tuple[str, str], str] = {}
        self._syncs: dict[str, SyncReport] = {}
        self._webhooks: dict[str, WebhookEvent] = {}
        self._seen_event_ids: set[str] = set()
        self._audit_log: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise IntegrationHubError(
                f"seq must be strictly increasing (last={self._last_seq}, saw={seq})"
            )
        self._last_seq = seq
        return seq

    def _audit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(integration_hub_audit_event(kind, seq, **detail))

    # -- apps -----------------------------------------------------------

    def register_app(
        self, app_id: str, seq: int, scopes: Any = ()
    ) -> AppRecord:
        """Pin an integration app (``app-N`` id)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                _check_app_id(app_id)
                scope_tuple = _check_scopes(app_id, scopes)
                self._app_counter += 1
                app_uid = f"app-{self._app_counter}"
                payload = _record_payload(
                    "app-record",
                    {
                        "app_uid": app_uid,
                        "app_id": app_id,
                        "scopes": list(scope_tuple),
                        "seq": seq,
                    },
                )
                record = AppRecord(
                    app_uid=app_uid,
                    app_id=app_id,
                    scopes=scope_tuple,
                    seq=seq,
                    record_digest=_sealed(payload),
                )
            except Exception:
                self._audit(KIND_AUDIT, seq, rejected="register-app")
                raise
            self._apps[app_uid] = record
            self._audit(KIND_APP_REGISTERED, seq, app_uid=app_uid,
                        app_id=app_id)
            return record

    def app(self, app_uid: str) -> AppRecord | None:
        """Read view: the app record for ``app_uid``, or ``None``."""
        if not isinstance(app_uid, str):
            raise IntegrationHubError("app_uid must be a string")
        return self._apps.get(app_uid)

    # -- connections ----------------------------------------------------

    def connect(
        self,
        app_uid: str,
        account_id: str,
        token_digest: str,
        seq: int,
        scopes: Any = (),
    ) -> ConnectionRecord:
        """Book a completed per-account connection (``conn-N`` id).

        ``token_digest`` pins the host-reported token handle — the raw
        token must never be passed in. One active connection per
        ``(app_uid, account_id)`` pair is allowed; a second active
        connect is refused fail-closed (disconnect first).
        """
        with self._lock:
            seq = self._next_seq(seq)
            try:
                if not isinstance(app_uid, str) or app_uid not in self._apps:
                    raise IntegrationHubError(
                        f"unknown app_uid: {app_uid!r}"
                    )
                app = self._apps[app_uid]
                _check_nonempty_str(account_id, "account_id")
                _check_digest(token_digest, "token_digest")
                if not scopes:
                    scope_tuple = app.scopes
                else:
                    scope_tuple = _check_scopes(app.app_id, scopes)
                key = (app_uid, account_id)
                if key in self._active_by_key:
                    raise IntegrationHubError(
                        "active connection already exists for this "
                        f"(app_uid, account_id): {self._active_by_key[key]}"
                    )
                self._conn_counter += 1
                connection_id = f"conn-{self._conn_counter}"
                payload = _record_payload(
                    "connection-record",
                    {
                        "connection_id": connection_id,
                        "app_uid": app_uid,
                        "account_id": account_id,
                        "status": STATUS_CONNECTED,
                        "scopes": list(scope_tuple),
                        "token_digest": token_digest,
                        "connected_seq": seq,
                        "seq": seq,
                        "prev_digest": _GENESIS,
                        "last_sync_seq": -1,
                    },
                )
                record = ConnectionRecord(
                    connection_id=connection_id,
                    app_uid=app_uid,
                    account_id=account_id,
                    status=STATUS_CONNECTED,
                    scopes=scope_tuple,
                    token_digest=token_digest,
                    connected_seq=seq,
                    seq=seq,
                    prev_digest=_GENESIS,
                    record_digest=_sealed(payload),
                    last_sync_seq=-1,
                )
            except Exception:
                self._audit(KIND_AUDIT, seq, rejected="connect")
                raise
            self._connections[connection_id] = record
            self._active_by_key[(app_uid, account_id)] = connection_id
            self._audit(KIND_CONNECTED, seq, connection_id=connection_id,
                        app_uid=app_uid)
            return record

    def disconnect(
        self, connection_id: str, seq: int, reason: str = ""
    ) -> ConnectionRecord:
        """Terminally disconnect one connection (``disconnected``)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                if (
                    not isinstance(connection_id, str)
                    or connection_id not in self._connections
                ):
                    raise IntegrationHubError(
                        f"unknown connection_id: {connection_id!r}"
                    )
                current = self._connections[connection_id]
                if current.status != STATUS_CONNECTED:
                    raise IntegrationHubError(
                        f"connection {connection_id} is already "
                        f"{current.status} (terminal)"
                    )
                if not isinstance(reason, str):
                    raise IntegrationHubError("reason must be a string")
                payload = _record_payload(
                    "connection-record",
                    {
                        "connection_id": connection_id,
                        "app_uid": current.app_uid,
                        "account_id": current.account_id,
                        "status": STATUS_DISCONNECTED,
                        "scopes": list(current.scopes),
                        "token_digest": current.token_digest,
                        "connected_seq": current.connected_seq,
                        "seq": seq,
                        "prev_digest": current.record_digest,
                        "last_sync_seq": current.last_sync_seq,
                    },
                )
                record = replace(
                    current,
                    status=STATUS_DISCONNECTED,
                    seq=seq,
                    prev_digest=current.record_digest,
                    record_digest=_sealed(payload),
                )
            except Exception:
                self._audit(KIND_AUDIT, seq, rejected="disconnect")
                raise
            self._connections[connection_id] = record
            self._active_by_key.pop(
                (current.app_uid, current.account_id), None
            )
            self._audit(KIND_DISCONNECTED, seq, connection_id=connection_id)
            return record

    def connection(self, connection_id: str) -> ConnectionRecord | None:
        """Read view: the connection record, or ``None`` for unknown ids."""
        if not isinstance(connection_id, str):
            raise IntegrationHubError("connection_id must be a string")
        return self._connections.get(connection_id)

    def status(self, connection_id: str) -> str | None:
        """Read view: the connection status, or ``None`` for unknown ids."""
        record = self.connection(connection_id)
        return record.status if record is not None else None

    # -- sync ------------------------------------------------------------

    def sync(
        self,
        connection_id: str,
        seq: int,
        outcome: str = SYNC_OK,
        created: int = 0,
        updated: int = 0,
        deleted: int = 0,
        record_digests: Any = (),
    ) -> SyncReport:
        """Book one sync run against a *connected* connection (``sync-N``).

        Counters are host-reported data. ``record_digests`` are
        ``sha256:`` pins of the host's record payloads — raw payloads
        never enter. The connection's sync cursor (``seq``) must
        advance monotonically.
        """
        with self._lock:
            seq = self._next_seq(seq)
            try:
                if (
                    not isinstance(connection_id, str)
                    or connection_id not in self._connections
                ):
                    raise IntegrationHubError(
                        f"unknown connection_id: {connection_id!r}"
                    )
                conn = self._connections[connection_id]
                if conn.status != STATUS_CONNECTED:
                    raise IntegrationHubError(
                        f"connection {connection_id} is {conn.status}: "
                        "sync refused fail-closed"
                    )
                if outcome not in _SYNC_OUTCOMES:
                    raise IntegrationHubError(
                        f"outcome must be one of {_SYNC_OUTCOMES}, "
                        f"saw {outcome!r}"
                    )
                for name, value in (
                    ("created", created),
                    ("updated", updated),
                    ("deleted", deleted),
                ):
                    if isinstance(value, bool) or not isinstance(value, int) \
                            or value < 0:
                        raise IntegrationHubError(
                            f"{name} must be a non-negative int"
                        )
                if not isinstance(record_digests, (tuple, list)):
                    raise IntegrationHubError(
                        "record_digests must be a tuple/list of digest pins"
                    )
                digest_tuple = tuple(
                    _check_digest(d, "record_digests[]")
                    for d in record_digests
                )
                if seq <= conn.last_sync_seq:
                    raise IntegrationHubError(
                        "sync seq must advance monotonically per connection "
                        f"(cursor={conn.last_sync_seq}, saw={seq})"
                    )
                self._sync_counter += 1
                sync_id = f"sync-{self._sync_counter}"
                payload = _record_payload(
                    "sync-report",
                    {
                        "sync_id": sync_id,
                        "connection_id": connection_id,
                        "outcome": outcome,
                        "records_created": created,
                        "records_updated": updated,
                        "records_deleted": deleted,
                        "cursor": seq,
                        "record_digests": list(digest_tuple),
                        "seq": seq,
                    },
                )
                report = SyncReport(
                    sync_id=sync_id,
                    connection_id=connection_id,
                    outcome=outcome,
                    records_created=created,
                    records_updated=updated,
                    records_deleted=deleted,
                    cursor=seq,
                    record_digests=digest_tuple,
                    seq=seq,
                    record_digest=_sealed(payload),
                )
            except Exception:
                self._audit(KIND_AUDIT, seq, rejected="sync")
                raise
            self._syncs[sync_id] = report
            conn_payload = _record_payload(
                "connection-record",
                {
                    "connection_id": conn.connection_id,
                    "app_uid": conn.app_uid,
                    "account_id": conn.account_id,
                    "status": conn.status,
                    "scopes": list(conn.scopes),
                    "token_digest": conn.token_digest,
                    "connected_seq": conn.connected_seq,
                    "seq": conn.seq,
                    "prev_digest": conn.record_digest,
                    "last_sync_seq": seq,
                },
            )
            self._connections[connection_id] = replace(
                conn,
                last_sync_seq=seq,
                record_digest=_sealed(conn_payload),
            )
            self._audit(KIND_SYNCED, seq, sync_id=sync_id,
                        connection_id=connection_id, outcome=outcome)
            return report

    # -- webhooks --------------------------------------------------------

    def webhook(
        self,
        app_uid: str,
        event_id: str,
        event_type: str,
        payload_digest: str,
        seq: int,
        signature_ok: bool = True,
    ) -> WebhookEvent:
        """Book one inbound webhook receipt (``wh-N`` id).

        ``signature_ok`` is the host's verification verdict booked as
        data (the module does not verify cryptographically). Replayed
        ``event_id`` values are refused fail-closed.
        """
        with self._lock:
            seq = self._next_seq(seq)
            try:
                if not isinstance(app_uid, str) or app_uid not in self._apps:
                    raise IntegrationHubError(
                        f"unknown app_uid: {app_uid!r}"
                    )
                _check_nonempty_str(event_id, "event_id")
                _check_event_type(event_type)
                _check_digest(payload_digest, "payload_digest")
                if not isinstance(signature_ok, bool):
                    raise IntegrationHubError(
                        "signature_ok must be a bool"
                    )
                if event_id in self._seen_event_ids:
                    raise IntegrationHubError(
                        f"replayed event_id refused: {event_id!r}"
                    )
                self._wh_counter += 1
                webhook_id = f"wh-{self._wh_counter}"
                payload = _record_payload(
                    "webhook-event",
                    {
                        "webhook_id": webhook_id,
                        "app_uid": app_uid,
                        "event_id": event_id,
                        "event_type": event_type,
                        "signature_ok": signature_ok,
                        "payload_digest": payload_digest,
                        "seq": seq,
                    },
                )
                event = WebhookEvent(
                    webhook_id=webhook_id,
                    app_uid=app_uid,
                    event_id=event_id,
                    event_type=event_type,
                    signature_ok=signature_ok,
                    payload_digest=payload_digest,
                    seq=seq,
                    record_digest=_sealed(payload),
                )
            except Exception:
                self._audit(KIND_AUDIT, seq, rejected="webhook")
                raise
            self._webhooks[webhook_id] = event
            self._seen_event_ids.add(event_id)
            self._audit(KIND_WEBHOOK, seq, webhook_id=webhook_id,
                        app_uid=app_uid, event_type=event_type)
            return event

    # -- views ------------------------------------------------------------

    def connection_ids(self) -> tuple:
        """Sorted connection ids."""
        return tuple(sorted(self._connections))

    def sync_ids(self) -> tuple:
        """Sorted sync ids."""
        return tuple(sorted(self._syncs))

    def webhook_ids(self) -> tuple:
        """Sorted webhook ids."""
        return tuple(sorted(self._webhooks))

    def get_sync(self, sync_id: str) -> SyncReport | None:
        """Read view: the sync report, or ``None`` for unknown ids."""
        if not isinstance(sync_id, str):
            raise IntegrationHubError("sync_id must be a string")
        return self._syncs.get(sync_id)

    def audit(self, seq: int) -> Mapping[str, Any]:
        """Summarize the hub state (counts + digest pin) as audit data."""
        _check_seq(seq, "seq")
        with self._lock:
            counts = {
                "apps": len(self._apps),
                "connections": len(self._connections),
                "syncs": len(self._syncs),
                "webhooks": len(self._webhooks),
            }
            pins = sorted(
                r.record_digest for r in self._apps.values()
            ) + sorted(
                r.record_digest for r in self._connections.values()
            ) + sorted(
                r.record_digest for r in self._syncs.values()
            ) + sorted(
                r.record_digest for r in self._webhooks.values()
            )
            payload = _record_payload(
                "hub-audit",
                {"counts": counts, "pins": pins, "seq": seq},
            )
            return integration_hub_audit_event(
                KIND_AUDIT,
                seq,
                counts=counts,
                state_digest=_sealed(payload),
            )

    def audit_log(self) -> tuple:
        """All audit events emitted so far."""
        return tuple(self._audit_log)


def _stdlib_only(path: str) -> None:
    """Guard: module must import stdlib only."""
    import ast

    tree = ast.parse(open(path).read())
    allowed = {
        "hashlib",
        "json",
        "dataclasses",
        "threading",
        "typing",
        "__future__",
        "ast",  # self-check helper only
    }
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    extras = imported - allowed
    if extras:
        raise AssertionError(f"non-stdlib imports: {sorted(extras)}")


def main() -> None:
    """Self-check: register, connect, sync, webhook, disconnect, audit."""
    hub = IntegrationHub()
    app = hub.register_app(APP_SLACK, 1, ("chat:write",))
    assert app.app_uid == "app-1"
    conn = hub.connect(
        app.app_uid, "acct-1", _PIN + "00" * 32, 2
    )
    assert conn.status == STATUS_CONNECTED
    assert hub.status(conn.connection_id) == STATUS_CONNECTED
    report = hub.sync(
        conn.connection_id, 3, created=2, updated=1,
        record_digests=[_PIN + "11" * 32],
    )
    assert report.outcome == SYNC_OK
    assert report.records_created == 2
    event = hub.webhook(
        app.app_uid, "evt-1", WEBHOOK_SYNC_COMPLETED, _PIN + "22" * 32, 4
    )
    assert event.signature_ok is True
    try:
        hub.webhook(
            app.app_uid, "evt-1", WEBHOOK_SYNC_COMPLETED,
            _PIN + "22" * 32, 5,
        )
        raise AssertionError("replay must be refused")
    except IntegrationHubError:
        pass
    closed = hub.disconnect(conn.connection_id, 6, reason="user")
    assert closed.status == STATUS_DISCONNECTED
    summary = hub.audit(7)
    assert summary["kind"] == KIND_AUDIT
    assert summary["detail"]["counts"]["syncs"] == 1
    _stdlib_only(__file__)
    print("integration-hub OK: register, connect, sync, webhook, "
          "replay-refusal, disconnect, audit")


if __name__ == "__main__":
    main()
