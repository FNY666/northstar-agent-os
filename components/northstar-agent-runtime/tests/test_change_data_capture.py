"""Tests for change_data_capture (Debezium-shaped CDC bookkeeping)."""

import ast
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import change_data_capture
from change_data_capture import (
    ChangeDataCapture,
    BadTableError,
    DuplicateTableError,
    UnknownTableError,
    BadChangeError,
    DuplicateChangeError,
    UnknownChangeError,
    BadOpError,
    OpEnvelopeError,
    BadPayloadError,
    BadConnectorError,
    ChangeStateError,
    SeqOrderError,
    ChangeDataCaptureError,
    change_data_capture_audit_event,
    CHANGE_DATA_CAPTURE_VERSION,
    CHANGE_DATA_CAPTURE_SCHEMA,
    KIND_SOURCE_REGISTERED,
    KIND_CAPTURED,
    KIND_EMITTED,
    KIND_REJECTED,
    OP_CREATE,
    OP_UPDATE,
    OP_DELETE,
    OP_READ,
)


def test_version_and_schema_pins():
    assert CHANGE_DATA_CAPTURE_VERSION == "change-data-capture.v1"
    assert CHANGE_DATA_CAPTURE_SCHEMA == "northstar.change-data-capture.v1"


def test_stdlib_only():
    tree = ast.parse(Path(change_data_capture.__file__).read_text())
    allowed = {
        "__future__", "hashlib", "threading", "dataclasses", "typing", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.split(".")[0]
                if name == "canonical_json":
                    continue  # stdlib-first fallback
                assert name in allowed, name
        elif isinstance(node, ast.ImportFrom):
            if node.module == "canonical_json":
                continue  # stdlib-first fallback
            assert node.module in allowed, node.module


def test_source_roundtrip_and_record_shape():
    ledger = ChangeDataCapture()
    rec = ledger.source("db.orders", 1)
    assert rec.table_id == "db.orders"
    assert rec.connector == "debezium"
    assert rec.registered_seq == 1
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    assert ledger.source_rec("db.orders") == rec
    assert ledger.source_ids() == ("db.orders",)
    # Custom connector name is booked.
    rec2 = ledger.source("db.users", 2, connector="debezium-mysql")
    assert rec2.connector == "debezium-mysql"
    assert ledger.source_ids() == ("db.orders", "db.users")
    # Tampered record fails verify().
    assert not replace(rec, table_id="db.evil").verify()


def test_source_duplicate_and_bad_inputs():
    ledger = ChangeDataCapture()
    ledger.source("db.orders", 1)
    with pytest.raises(DuplicateTableError):
        ledger.source("db.orders", 2)
    # Failed mutation consumed its seq: seq 2 is now taken.
    with pytest.raises(SeqOrderError):
        ledger.source("db.other", 2)
    cases = [
        ("", 3),            # empty table id
        (123, 4),           # non-str table id
        (True, 5),          # bool table id
        ("   ", 6),         # blank table id
        ("x" * 257, 7),     # too long
    ]
    for table_id, seq in cases:
        with pytest.raises(BadTableError):
            ledger.source(table_id, seq)
    with pytest.raises(BadConnectorError):
        ledger.source("db.ok", 8, connector="")
    with pytest.raises(BadConnectorError):
        ledger.source("db.ok2", 9, connector=123)


def test_capture_envelope_happy_paths():
    ledger = ChangeDataCapture()
    ledger.source("db.orders", 1)
    created = ledger.capture(
        "chg-1", "db.orders", OP_CREATE, 2,
        after={"id": 1, "total": 9.5},
    )
    assert created.op == "c"
    assert created.before_digest == ""
    assert created.after_digest.startswith("sha256:")
    assert created.captured_seq == 2
    assert created.verify()
    updated = ledger.capture(
        "chg-2", "db.orders", OP_UPDATE, 3,
        before={"id": 1, "total": 9.5},
        after={"id": 1, "total": 10.0},
    )
    assert updated.op == "u"
    assert updated.before_digest.startswith("sha256:")
    assert updated.after_digest.startswith("sha256:")
    assert updated.verify()
    deleted = ledger.capture(
        "chg-3", "db.orders", OP_DELETE, 4,
        before={"id": 1, "total": 10.0},
    )
    assert deleted.op == "d"
    assert deleted.after_digest == ""
    assert deleted.before_digest.startswith("sha256:")
    assert deleted.verify()
    read = ledger.capture(
        "chg-4", "db.orders", OP_READ, 5,
        after={"id": 2, "total": 1.0},
    )
    assert read.op == "r"
    assert read.before_digest == ""
    assert read.verify()
    assert ledger.change("chg-2") == updated
    assert ledger.change_ids() == ("chg-1", "chg-2", "chg-3", "chg-4")
    # Deterministic digests across instances.
    twin = ChangeDataCapture()
    twin.source("db.orders", 1)
    twin_created = twin.capture(
        "chg-1", "db.orders", OP_CREATE, 2,
        after={"id": 1, "total": 9.5},
    )
    assert twin_created.digest == created.digest


def test_capture_envelope_contract_refused():
    ledger = ChangeDataCapture()
    ledger.source("db.orders", 1)
    cases = [
        # (change_id, op, before, after)
        ("e-1", "c", {"id": 1}, {"id": 1}),       # create must not carry before
        ("e-2", "c", None, None),                 # create requires after
        ("e-3", "r", {"id": 1}, {"id": 1}),       # snapshot-read, no before
        ("e-4", "r", None, None),                 # snapshot-read requires after
        ("e-5", "d", {"id": 1}, {"id": 1}),       # delete must not carry after
        ("e-6", "d", None, None),                 # delete requires before
        ("e-7", "u", None, {"id": 1}),            # update requires before
        ("e-8", "u", {"id": 1}, None),            # update requires after
    ]
    seq = 2
    for change_id, op, before, after in cases:
        with pytest.raises(OpEnvelopeError):
            ledger.capture(change_id, "db.orders", op, seq,
                           before=before, after=after)
        seq += 1
    # Every refusal was fail-closed and consumed its seq.
    with pytest.raises(SeqOrderError):
        ledger.source("db.other", seq - 1)


def test_capture_bad_payloads_refused():
    ledger = ChangeDataCapture()
    ledger.source("db.orders", 1)
    cases = [
        (float("nan"), "NaN float"),
        (float("inf"), "infinite float"),
        (2**54, "unsafe int"),
        (-(2**54), "unsafe negative int"),
        ("x" * 65537, "oversize str"),
        ({123: "v"}, "non-str dict key"),
        ({True: "v"}, "bool dict key"),
        (object(), "unencodable type"),
    ]
    seq = 2
    for value, _label in cases:
        with pytest.raises(BadPayloadError):
            ledger.capture(f"bad-{seq}", "db.orders", "c", seq,
                           after={"val": value})
        seq += 1
    # Deeply nested rows are refused.
    deep = {}
    cursor = deep
    for _ in range(20):
        cursor["n"] = {}
        cursor = cursor["n"]
    with pytest.raises(BadPayloadError):
        ledger.capture("bad-deep", "db.orders", "c", seq, after=deep)
    seq += 1
    # Bad op codes are refused.
    for bad_op in ["x", "create", "", None, True, 1]:
        with pytest.raises(BadOpError):
            ledger.capture(f"op-{seq}", "db.orders", bad_op, seq,
                           after={"id": 1})
        seq += 1


def test_capture_unknown_table_and_duplicate_id():
    ledger = ChangeDataCapture()
    with pytest.raises(UnknownTableError):
        ledger.capture("chg-1", "db.missing", "c", 1, after={"id": 1})
    ledger.source("db.orders", 2)
    rec = ledger.capture("chg-1", "db.orders", "c", 3, after={"id": 1})
    assert rec.verify()
    with pytest.raises(DuplicateChangeError):
        ledger.capture("chg-1", "db.orders", "c", 4, after={"id": 2})
    # Failed mutation consumed its seq: seq 4 is taken.
    with pytest.raises(SeqOrderError):
        ledger.capture("chg-2", "db.orders", "c", 4, after={"id": 2})
    # Retired ids are never recycled, even for other tables.
    ledger.source("db.users", 5)
    with pytest.raises(DuplicateChangeError):
        ledger.capture("chg-1", "db.users", "c", 6, after={"id": 9})


def test_emit_roundtrip_and_record_shape():
    ledger = ChangeDataCapture()
    ledger.source("db.orders", 1)
    ledger.capture("chg-1", "db.orders", "c", 2, after={"id": 1})
    rec = ledger.emit("chg-1", 3)
    assert rec.change_id == "chg-1"
    assert rec.table_id == "db.orders"
    assert rec.op == "c"
    assert rec.captured_seq == 2
    assert rec.seq == 3
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    assert ledger.emission("chg-1") == rec
    assert ledger.emission("chg-missing") is None
    assert ledger.pending() == ()
    assert ledger.pending("db.orders") == ()
    # Tampered emission fails verify().
    assert not replace(rec, op="d").verify()


def test_emit_unknown_and_double_emit_refused():
    ledger = ChangeDataCapture()
    ledger.source("db.orders", 1)
    with pytest.raises(UnknownChangeError):
        ledger.emit("chg-missing", 2)
    with pytest.raises(BadChangeError):
        ledger.emit("", 3)
    ledger.capture("chg-1", "db.orders", "c", 4, after={"id": 1})
    ledger.emit("chg-1", 5)
    with pytest.raises(ChangeStateError):
        ledger.emit("chg-1", 6)
    # Failed mutation consumed its seq.
    with pytest.raises(SeqOrderError):
        ledger.emit("chg-1", 6)


def test_seq_ordering_and_failed_mutation_consumes_seq():
    ledger = ChangeDataCapture()
    ledger.source("db.orders", 1)
    # Rewind raises without consuming.
    with pytest.raises(SeqOrderError):
        ledger.source("db.other", 1)
    ledger.source("db.other", 2)  # seq 1 still usable (rewind consumed nothing)
    # Non-int seqs are refused without consuming.
    for bad in (True, 2.0, "3", None, -1):
        with pytest.raises(SeqOrderError):
            ledger.capture("bad", "db.orders", "c", bad, after={"id": 1})
    # Failed mutations consume their seq.
    with pytest.raises(DuplicateTableError):
        ledger.source("db.orders", 3)
    with pytest.raises(SeqOrderError):
        ledger.source("db.third", 3)
    # A rejected capture is audited.
    with pytest.raises(OpEnvelopeError):
        ledger.capture("bad-env", "db.orders", "c", 4,
                       before={"id": 1}, after={"id": 1})
    kinds = [row["kind"] for row in ledger.audit_log()]
    assert KIND_REJECTED in kinds
    rejected = [r for r in ledger.audit_log()
                if r["kind"] == KIND_REJECTED][-1]
    assert rejected["detail"]["error"] == "OpEnvelopeError"
    assert rejected["seq"] == 4


def test_offset_view_shape_and_read_purity():
    ledger = ChangeDataCapture()
    ledger.source("db.orders", 1)
    ledger.source("db.users", 2)
    ledger.capture("o-1", "db.orders", "c", 3, after={"id": 1})
    ledger.capture("o-2", "db.orders", "u", 4,
                   before={"id": 1}, after={"id": 1, "t": 2})
    ledger.capture("u-1", "db.users", "c", 5, after={"id": 7})
    ledger.emit("o-2", 6)
    off = ledger.offset("db.orders", 7)
    assert off.table_id == "db.orders"
    assert off.last_captured_seq == 4
    assert off.last_emitted_seq == 6
    assert off.captured_count == 2
    assert off.emitted_count == 1
    assert off.pending_count == 1
    assert off.pending_ids == ("o-1",)
    assert off.verify()
    # Pending sorted deterministically.
    ledger.capture("o-0", "db.orders", "c", 8, after={"id": 0})
    off2 = ledger.offset("db.orders", 9)
    assert off2.pending_ids == ("o-0", "o-1")
    assert off2.verify()
    # Pure read: same seq re-usable, no audit row written.
    rows_before = len(ledger.audit_log())
    again = ledger.offset("db.orders", 9)
    assert again == off2
    assert len(ledger.audit_log()) == rows_before
    # offset() at a stale seq is fine (views validate shape only).
    stale = ledger.offset("db.orders", 1)
    assert stale.pending_ids == ("o-0", "o-1")
    # Other tables are independent.
    uoff = ledger.offset("db.users", 10)
    assert uoff.pending_ids == ("u-1",)
    assert uoff.emitted_count == 0
    # Empty table: zero position as data.
    ledger.source("db.empty", 11)
    eoff = ledger.offset("db.empty", 12)
    assert eoff.captured_count == 0
    assert eoff.last_captured_seq == 0
    assert eoff.pending_ids == ()
    assert eoff.verify()


def test_offset_unknown_table_refused():
    ledger = ChangeDataCapture()
    with pytest.raises(UnknownTableError):
        ledger.offset("db.missing", 1)
    with pytest.raises(BadTableError):
        ledger.offset("", 1)
    # offset() does not consume seq: the next mutation may reuse seq 1.
    ledger.source("db.orders", 1)


def test_audit_shapes_and_banned_keys():
    ledger = ChangeDataCapture()
    ledger.source("db.orders", 1)
    ledger.capture("chg-1", "db.orders", "c", 2, after={"id": 1})
    ledger.emit("chg-1", 3)
    try:
        ledger.source("db.orders", 4)
    except DuplicateTableError:
        pass
    log = ledger.audit_log()
    by_kind = {}
    for row in log:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == CHANGE_DATA_CAPTURE_VERSION
        by_kind.setdefault(row["kind"], []).append(row)
    for kind in (KIND_SOURCE_REGISTERED, KIND_CAPTURED, KIND_EMITTED,
                 KIND_REJECTED):
        assert kind in by_kind, kind
    captured = by_kind[KIND_CAPTURED][0]["detail"]
    assert captured["change_id"] == "chg-1"
    assert captured["op"] == "c"
    assert captured["after_digest"].startswith("sha256:")
    # Row halves never cross the audit boundary.
    for row in log:
        for banned in ("before", "after", "value", "payload", "raw"):
            assert banned not in row["detail"], banned
    # The builder itself bans payload keys and bad kinds.
    with pytest.raises(ChangeDataCaptureError):
        change_data_capture_audit_event(
            KIND_CAPTURED, {"before": {"id": 1}}, 10)
    with pytest.raises(ChangeDataCaptureError):
        change_data_capture_audit_event(
            KIND_CAPTURED, {"after": {"id": 1}}, 10)
    with pytest.raises(ChangeDataCaptureError):
        change_data_capture_audit_event("nope.kind", {}, 10)


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, change_data_capture.__file__],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "change-data-capture OK" in proc.stdout
