"""Tests for integration_hub: register, connect, sync, webhook, audit."""

import ast
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from integration_hub import (
    AUDIT_SCHEMA,
    INTEGRATION_HUB_SCHEMA,
    INTEGRATION_HUB_VERSION,
    APP_SLACK,
    APP_GITHUB,
    STATUS_CONNECTED,
    STATUS_DISCONNECTED,
    SYNC_OK,
    WEBHOOK_SYNC_COMPLETED,
    KIND_APP_REGISTERED,
    KIND_CONNECTED,
    KIND_DISCONNECTED,
    KIND_SYNCED,
    KIND_WEBHOOK,
    KIND_AUDIT,
    IntegrationHub,
    IntegrationHubError,
    integration_hub_audit_event,
    main,
)

PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def make_hub():
    hub = IntegrationHub()
    app = hub.register_app(APP_SLACK, 1, ("chat:write",))
    return hub, app


def test_pins():
    assert INTEGRATION_HUB_VERSION == "integration-hub.v1"
    assert INTEGRATION_HUB_SCHEMA == "northstar.integration-hub.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_register_roundtrip():
    hub = IntegrationHub()
    app = hub.register_app(APP_GITHUB, 1, ("read:org", "repo"))
    assert app.app_uid == "app-1"
    assert app.scopes == ("read:org", "repo")
    assert len(app.record_digest) == 64
    assert hub.app("app-1") is app
    assert hub.app("nope") is None
    kinds = [e["kind"] for e in hub.audit_log()]
    assert KIND_APP_REGISTERED in kinds


def test_register_bad_app_id():
    hub = IntegrationHub()
    try:
        hub.register_app("tiktok", 1)
        raise AssertionError("must refuse unknown app_id")
    except IntegrationHubError:
        pass


def test_register_bad_scope():
    hub = IntegrationHub()
    try:
        hub.register_app(APP_SLACK, 1, ("admin:root",))
        raise AssertionError("must refuse unpinned scope")
    except IntegrationHubError:
        pass


def test_connect_roundtrip_defaults_scopes():
    hub, app = make_hub()
    conn = hub.connect(app.app_uid, "acct-7", PIN, 2)
    assert conn.connection_id == "conn-1"
    assert conn.status == STATUS_CONNECTED
    assert conn.scopes == ("chat:write",)
    assert conn.token_digest == PIN
    assert conn.last_sync_seq == -1
    assert hub.status("conn-1") == STATUS_CONNECTED
    assert hub.status("nope") is None
    kinds = [e["kind"] for e in hub.audit_log()]
    assert KIND_CONNECTED in kinds


def test_connect_duplicate_active_refused():
    hub, app = make_hub()
    hub.connect(app.app_uid, "acct-7", PIN, 2)
    try:
        hub.connect(app.app_uid, "acct-7", PIN2, 3)
        raise AssertionError("must refuse duplicate active connection")
    except IntegrationHubError:
        pass
    # failed mutation consumes its seq: next good mutation needs seq 4
    try:
        hub.connect(app.app_uid, "acct-8", PIN2, 3)
        raise AssertionError("seq 3 already consumed by failed mutation")
    except IntegrationHubError:
        pass
    conn = hub.connect(app.app_uid, "acct-8", PIN2, 4)
    assert conn.connection_id == "conn-2"


def test_connect_unknown_app():
    hub = IntegrationHub()
    try:
        hub.connect("app-99", "acct-1", PIN, 1)
        raise AssertionError("must refuse unknown app_uid")
    except IntegrationHubError:
        pass


def test_sync_happy_path_cursor():
    hub, app = make_hub()
    conn = hub.connect(app.app_uid, "acct-7", PIN, 2)
    report = hub.sync(
        conn.connection_id, 3, created=2, updated=1, deleted=0,
        record_digests=[PIN2, PIN3],
    )
    assert report.sync_id == "sync-1"
    assert report.outcome == SYNC_OK
    assert report.records_created == 2
    assert report.record_digests == (PIN2, PIN3)
    assert report.cursor == 3
    assert hub.get_sync("sync-1") is report
    assert hub.get_sync("nope") is None
    # cursor advanced on the connection
    conn2 = hub.connection(conn.connection_id)
    assert conn2.last_sync_seq == 3
    kinds = [e["kind"] for e in hub.audit_log()]
    assert KIND_SYNCED in kinds


def test_sync_disconnected_refused():
    hub, app = make_hub()
    conn = hub.connect(app.app_uid, "acct-7", PIN, 2)
    hub.disconnect(conn.connection_id, 3, reason="user")
    try:
        hub.sync(conn.connection_id, 4)
        raise AssertionError("sync on disconnected must be refused")
    except IntegrationHubError:
        pass


def test_sync_cursor_rewind_refused():
    hub, app = make_hub()
    conn = hub.connect(app.app_uid, "acct-7", PIN, 2)
    hub.sync(conn.connection_id, 3)
    # seq 4 consumed by the failed attempt (mutation seq must still increase)
    try:
        hub.sync(conn.connection_id, 3)
        raise AssertionError("cursor rewind must be refused")
    except IntegrationHubError:
        pass


def test_disconnect_terminal():
    hub, app = make_hub()
    conn = hub.connect(app.app_uid, "acct-7", PIN, 2)
    closed = hub.disconnect(conn.connection_id, 3, reason="user")
    assert closed.status == STATUS_DISCONNECTED
    assert hub.status(conn.connection_id) == STATUS_DISCONNECTED
    try:
        hub.disconnect(conn.connection_id, 4)
        raise AssertionError("double disconnect must be refused")
    except IntegrationHubError:
        pass
    kinds = [e["kind"] for e in hub.audit_log()]
    assert KIND_DISCONNECTED in kinds
    # reconnect after disconnect is allowed (fresh id)
    conn2 = hub.connect(app.app_uid, "acct-7", PIN2, 5)
    assert conn2.connection_id == "conn-2"


def test_webhook_roundtrip_and_replay():
    hub, app = make_hub()
    event = hub.webhook(
        app.app_uid, "evt-1", WEBHOOK_SYNC_COMPLETED, PIN, 2
    )
    assert event.webhook_id == "wh-1"
    assert event.signature_ok is True
    assert len(event.record_digest) == 64
    kinds = [e["kind"] for e in hub.audit_log()]
    assert KIND_WEBHOOK in kinds
    try:
        hub.webhook(app.app_uid, "evt-1", WEBHOOK_SYNC_COMPLETED, PIN, 3)
        raise AssertionError("replayed event_id must be refused")
    except IntegrationHubError:
        pass


def test_webhook_bad_event_type():
    hub, app = make_hub()
    try:
        hub.webhook(app.app_uid, "evt-9", "nope", PIN, 2)
        raise AssertionError("must refuse unknown event_type")
    except IntegrationHubError:
        pass


def test_audit_shapes_and_bans():
    hub, app = make_hub()
    event = integration_hub_audit_event(KIND_AUDIT, 2, counts={"a": 1})
    assert event["schema"] == "audit.ndjson/1"
    assert event["module"] == "integration_hub"
    assert event["module_version"] == "integration-hub.v1"
    for banned in ("token", "secret", "payload", "account"):
        try:
            integration_hub_audit_event(KIND_AUDIT, 3, **{banned: "x"})
            raise AssertionError(f"must ban {banned!r} from audit")
        except IntegrationHubError:
            pass
    try:
        integration_hub_audit_event("nope", 3)
        raise AssertionError("must refuse unknown audit kind")
    except IntegrationHubError:
        pass


def test_seq_monotonicity():
    hub = IntegrationHub()
    hub.register_app(APP_SLACK, 1)
    try:
        hub.register_app(APP_GITHUB, 1)
        raise AssertionError("seq rewind must be refused")
    except IntegrationHubError:
        pass
    try:
        hub.register_app(APP_GITHUB, True)
        raise AssertionError("bool seq must be refused")
    except IntegrationHubError:
        pass


def test_audit_summary_counts():
    hub, app = make_hub()
    conn = hub.connect(app.app_uid, "acct-7", PIN, 2)
    hub.sync(conn.connection_id, 3)
    summary = hub.audit(4)
    assert summary["kind"] == KIND_AUDIT
    assert summary["detail"]["counts"] == {
        "apps": 1, "connections": 1, "syncs": 1, "webhooks": 0,
    }
    assert len(summary["detail"]["state_digest"]) == 64


def test_stdlib_only():
    path = os.path.join(os.path.dirname(__file__), "..", "integration_hub.py")
    tree = ast.parse(open(path).read())
    allowed = {"hashlib", "json", "dataclasses", "threading", "typing",
               "__future__", "ast"}  # ast: self-check helper only
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported - allowed == set(), imported - allowed


def test_main():
    main()
