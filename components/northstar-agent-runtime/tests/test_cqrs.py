"""Tests for cqrs."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import cqrs
from cqrs import (
    CQRS,
    CQRSError,
    BadCommandError,
    BadDigestError,
    BadProjectorError,
    BadQueryError,
    BadUpToError,
    DuplicateCommandError,
    DuplicateProjectorError,
    DuplicateQueryError,
    SeqOrderError,
    UnknownCommandError,
    UnknownProjectorError,
    AuditKindError,
    cqrs_audit_event,
)


def _pin(*parts: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(
        "\x00".join(parts).encode("utf-8")).hexdigest()


# 1. version + schema pins ---------------------------------------------------


def test_version_and_schema_pins():
    assert cqrs.CQRS_VERSION == "cqrs.v1"
    assert cqrs.CQRS_SCHEMA == "northstar.cqrs.v1"
    assert cqrs.AUDIT_SCHEMA == "audit.ndjson/1"


# 2. stdlib-only -----------------------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(Path(cqrs.__file__).read_text())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing",
        "json", "canonical_json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3. register_projector roundtrip + duplicate + bad ids -------------------------------


def test_register_projector_roundtrip():
    ledger = CQRS()
    rec = ledger.register_projector("orders-read", 1)
    assert rec.projector_id == "orders-read"
    assert rec.verify()
    assert ledger.projector_ids(2) == ("orders-read",)
    assert ledger.projection_cursor("orders-read", 2) == 0
    assert ledger.projector_state("orders-read", 2) == cqrs.GENESIS_STATE_DIGEST


def test_register_projector_duplicate_and_bad_ids():
    ledger = CQRS()
    ledger.register_projector("p", 1)
    with pytest.raises(DuplicateProjectorError):
        ledger.register_projector("p", 2)
    s = 3
    for bad in ["", 123, None, True, "x" * 257]:
        with pytest.raises(CQRSError):
            ledger.register_projector(bad, s)
        s += 1


# 4. command roundtrip + digest determinism + frozen -----------------------------------


def test_command_roundtrip_frozen():
    ledger = CQRS()
    pin = _pin("order", "1")
    rec = ledger.command("cmd-1", "PlaceOrder", pin, 1)
    assert rec.log_position == 1
    assert rec.verify()
    assert ledger.command_ids(2) == ("cmd-1",)
    rec2 = ledger.command_record("cmd-1", 2)
    assert rec2 == rec
    with pytest.raises(Exception):
        rec.command_id = "nope"  # frozen
    # digest deterministic across instances
    other = CQRS()
    rec_b = other.command("cmd-1", "PlaceOrder", pin, 1)
    assert rec_b.digest == rec.digest


def test_command_duplicate_and_bad_inputs():
    ledger = CQRS()
    pin = _pin("p")
    ledger.command("c", "T", pin, 1)
    with pytest.raises(DuplicateCommandError):
        ledger.command("c", "T", pin, 2)
    bad_digests = ["nope", "sha256:" + "zz" * 32, "md5:" + "a" * 32,
                   123, None, True]
    s = 3
    for bad in bad_digests:
        with pytest.raises(BadDigestError):
            ledger.command(f"c{s}", "T", bad, s)
        s += 1
    for bad in ["", None, True]:
        with pytest.raises(BadCommandError):
            ledger.command(bad, "T", pin, s)
        s += 1
    with pytest.raises(UnknownCommandError):
        ledger.command_record("missing", s)


# 6. project applies in order + cursor + state digest -------------------------------------


def test_project_applies_and_advances_cursor():
    ledger = CQRS()
    ledger.register_projector("r", 1)
    p1 = _pin("a")
    p2 = _pin("b")
    ledger.command("c1", "T", p1, 2)
    ledger.command("c2", "T", p2, 3)
    before = ledger.projector_state("r", 3)
    rec = ledger.project("r", 4)
    assert rec.applied_command_ids == ("c1", "c2")
    assert rec.from_cursor == 0 and rec.to_cursor == 3
    assert rec.verify()
    assert ledger.projection_cursor("r", 4) == 3
    after = ledger.projector_state("r", 4)
    assert after != before


# 7. project upto_seq partial application ---------------------------------------------------


def test_project_upto_seq_partial():
    ledger = CQRS()
    ledger.register_projector("r", 1)
    ledger.command("c1", "T", _pin("a"), 2)
    ledger.command("c2", "T", _pin("b"), 3)
    rec = ledger.project("r", 4, upto_seq=2)
    assert rec.applied_command_ids == ("c1",)
    assert rec.to_cursor == 2
    assert ledger.projection_cursor("r", 4) == 2
    rec2 = ledger.project("r", 5)
    assert rec2.applied_command_ids == ("c2",)
    assert ledger.projection_cursor("r", 5) == 3


# 8. project no-op when caught up --------------------------------------------------------------


def test_project_noop_when_caught_up():
    ledger = CQRS()
    ledger.register_projector("r", 1)
    rec = ledger.project("r", 2)
    assert rec.applied_command_ids == ()
    assert rec.to_cursor == 0
    assert ledger.projection_cursor("r", 2) == 0


# 9. project unknown projector / bad upto -----------------------------------------------------


def test_project_unknown_projector_and_bad_upto():
    ledger = CQRS()
    with pytest.raises(UnknownProjectorError):
        ledger.project("nope", 1)
    ledger.register_projector("r", 2)
    with pytest.raises(BadUpToError):
        ledger.project("r", 3, upto_seq=-1)
    with pytest.raises(BadUpToError):
        ledger.project("r", 4, upto_seq=True)


# 10. query roundtrip: fresh -------------------------------------------------------------------


def test_query_fresh():
    ledger = CQRS()
    ledger.register_projector("r", 1)
    ledger.command("c1", "T", _pin("a"), 2)
    ledger.project("r", 3)
    q = ledger.query("q1", "OrderStatus", "r", 4)
    assert q.verify()
    assert q.stale is False
    assert q.state_digest == ledger.projector_state("r", 4)
    assert q.projector_cursor == 2
    assert q.write_head == 2


# 11. query stale after new command ---------------------------------------------------------------


def test_query_stale_when_projector_lags():
    ledger = CQRS()
    ledger.register_projector("r", 1)
    ledger.command("c1", "T", _pin("a"), 2)
    ledger.project("r", 3)
    ledger.command("c2", "T", _pin("b"), 4)
    q = ledger.query("q1", "OrderStatus", "r", 5)
    assert q.stale is True
    assert q.projector_cursor == 2
    assert q.write_head == 4


# 12. query unknown projector / duplicate / bad inputs ----------------------------------------------


def test_query_unknown_projector_duplicate_bad_inputs():
    ledger = CQRS()
    with pytest.raises(UnknownProjectorError):
        ledger.query("q1", "T", "nope", 1)
    ledger.register_projector("r", 2)
    ledger.query("q1", "T", "r", 3)
    with pytest.raises(DuplicateQueryError):
        ledger.query("q1", "T", "r", 4)
    with pytest.raises(BadQueryError):
        ledger.query("", "T", "r", 5)


# 13. seq ordering + failed mutation consumes seq --------------------------------------------------------


def test_seq_ordering_and_failed_mutation_consumes_seq():
    ledger = CQRS()
    ledger.command("c1", "T", _pin("a"), 1)
    with pytest.raises(SeqOrderError):
        ledger.command("c2", "T", _pin("b"), 1)  # rewind
    with pytest.raises(CQRSError):
        ledger.command("c2", "T", _pin("b"), True)  # bool refused
    # failed duplicate consumes its seq: next mutation must exceed it
    with pytest.raises(DuplicateCommandError):
        ledger.command("c1", "T", _pin("a"), 2)
    with pytest.raises(SeqOrderError):
        ledger.command("c2", "T", _pin("b"), 2)
    ledger.command("c2", "T", _pin("b"), 3)
    # pure read views do not consume seq
    assert ledger.write_head(4) == 3
    ledger.command("c3", "T", _pin("c"), 4)


# 14. audit shapes + banned keys + bad kind ----------------------------------------------------------------


def test_audit_shapes_and_banned_keys():
    ledger = CQRS()
    ledger.register_projector("r", 1)
    ledger.command("c1", "T", _pin("a"), 2)
    kinds = [e["kind"] for e in ledger.audit_log()]
    assert kinds == [
        "cqrs.projector-registered",
        "cqrs.command-booked",
    ]
    ev = ledger.audit_log()[0]
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["module"] == "cqrs"
    with pytest.raises(CQRSError):
        cqrs_audit_event("cqrs.command-booked", 9, payload={"x": 1})
    with pytest.raises(AuditKindError):
        cqrs_audit_event("nope", 9)


# 15. main() subprocess self-check --------------------------------------------------------------------------


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, cqrs.__file__],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0
    assert "cqrs OK" in proc.stdout
