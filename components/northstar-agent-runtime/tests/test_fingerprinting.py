"""Targeted tests for the fingerprinting module (15 tests)."""

from __future__ import annotations

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import fingerprinting
from fingerprinting import (
    AlreadyIndexedError,
    AuditKindError,
    BadFeaturesError,
    BadItemError,
    BadToleranceError,
    DuplicateItemError,
    Fingerprinting,
    SeqOrderError,
    UnknownItemError,
    fingerprinting_audit_event,
)

HERE = Path(__file__).resolve().parent


def _fresh() -> Fingerprinting:
    return Fingerprinting()


# 1. version/schema pins -------------------------------------------------


def test_version_and_schema_pins():
    assert fingerprinting.FINGERPRINTING_VERSION == "fingerprinting.v1"
    assert fingerprinting.SCHEMA_PIN == "northstar.fingerprinting.v1"


# 2. stdlib-only AST check ------------------------------------------------


def test_stdlib_only():
    tree = ast.parse((HERE.parent / "fingerprinting.py").read_text())
    allowed = {
        "hashlib", "math", "threading", "dataclasses", "typing",
        "__future__", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or node.module.split(".")[0] in allowed


# 3. hash roundtrip -------------------------------------------------------


def test_hash_roundtrip():
    ledger = _fresh()
    rec = ledger.hash("track-1", (0.1, 0.2, 0.3, 0.4), 0)
    assert rec.fingerprint_id == "fp-1"
    assert rec.item_id == "track-1"
    assert rec.feature_count == 4
    assert rec.feature_digest.startswith("sha256:")
    assert rec.schema == "northstar.fingerprinting.v1"
    assert rec.verify(fingerprinting._quantize((0.1, 0.2, 0.3, 0.4)))
    assert not rec.verify(fingerprinting._quantize((0.9, 0.9, 0.9, 0.9)))
    assert ledger.fingerprint_id_for("track-1") == "fp-1"
    assert ledger.item_ids() == ("track-1",)
    frozen = ledger.fingerprint("fp-1")
    with pytest.raises(Exception):
        frozen.item_id = "other"  # frozen dataclass


# 4. hash duplicate + seq-burn --------------------------------------------


def test_hash_duplicate_seq_burn():
    ledger = _fresh()
    ledger.hash("track-1", (0.1,), 0)
    before = len(ledger.audit_log())
    with pytest.raises(DuplicateItemError):
        ledger.hash("track-1", (0.2,), 1)
    assert len(ledger.audit_log()) == before + 1  # rejected row booked
    assert ledger.audit_log()[-1]["kind"] == "fingerprinting.rejected"
    # seq 1 was consumed by the failed mutation
    with pytest.raises(SeqOrderError):
        ledger.hash("track-2", (0.3,), 1)
    ledger.hash("track-2", (0.3,), 2)


# 5. bad-features table ---------------------------------------------------


def test_hash_bad_features_table():
    bad_inputs = [
        (),  # empty
        "not-a-sequence",
        (True, 0.1),  # bool refused
        (0.1, float("nan")),  # non-finite
        (0.1, float("inf")),  # non-finite
        (0.1, "x"),  # non-number
        (0.1, None),  # non-number
    ]
    for i, bad in enumerate(bad_inputs):
        ledger = _fresh()
        seq = 2 * i
        with pytest.raises(BadFeaturesError):
            ledger.hash("item", bad, seq)
        assert len(ledger.audit_log()) == 1  # rejected booked
        assert ledger.audit_log()[0]["kind"] == "fingerprinting.rejected"
    # bad item ids
    for i, bad_id in enumerate(["", "x" * 257, 123, None]):
        ledger = _fresh()
        with pytest.raises(BadItemError):
            ledger.hash(bad_id, (0.1,), 10 + i)


# 6. match identical features ---------------------------------------------


def test_match_identical():
    ledger = _fresh()
    rec = ledger.hash("track-1", (0.1, 0.2, 0.3), 0)
    report = ledger.match(rec.fingerprint_id, (0.1, 0.2, 0.3), 1)
    assert report.match is True
    assert report.distance == 0.0
    assert report.tolerance == 0.25
    assert report.item_id == "track-1"
    assert report.digest.startswith("sha256:")
    assert ledger.audit_log()[-1]["kind"] == "fingerprinting.matched"


# 7. match non-match as data ----------------------------------------------


def test_match_no_match_as_data():
    ledger = _fresh()
    rec = ledger.hash("track-1", (0.0, 0.0, 0.0, 0.0), 0)
    report = ledger.match(rec.fingerprint_id, (1.0, 1.0, 1.0, 1.0), 1, tolerance=0.25)
    assert report.distance == 1.0
    assert report.match is False  # verdict is data, never raised
    assert ledger.audit_log()[-1]["kind"] == "fingerprinting.matched"
    # borderline: tolerance 1.0 always matches
    report2 = ledger.match(rec.fingerprint_id, (1.0, 1.0, 1.0, 1.0), 2, tolerance=1.0)
    assert report2.match is True


# 8. match unknown fingerprint + bad inputs --------------------------------


def test_match_unknown_and_bad_inputs():
    ledger = _fresh()
    ledger.hash("track-1", (0.1, 0.2), 0)
    fp = ledger.fingerprint_id_for("track-1")
    with pytest.raises(UnknownItemError):
        ledger.match("fp-999", (0.1, 0.2), 1)
    with pytest.raises(BadFeaturesError):
        ledger.match(fp, (0.1,), 2)  # length mismatch
    for i, bad_tol in enumerate([-0.1, 1.5, True, float("nan"), "x"]):
        with pytest.raises(BadToleranceError):
            ledger.match(fp, (0.1, 0.2), 10 + i, tolerance=bad_tol)


# 9. index roundtrip + duplicate + unknown ----------------------------------


def test_index_lifecycle():
    ledger = _fresh()
    rec = ledger.hash("track-1", (0.1, 0.2), 0)
    entry = ledger.index("track-1", 1)
    assert entry.item_id == "track-1"
    assert entry.fingerprint_id == rec.fingerprint_id
    assert entry.bucket_prefix == format(fingerprinting._quantize((0.1, 0.2))[0] % 256, "02x")
    assert ledger.indexed_ids() == ("track-1",)
    with pytest.raises(AlreadyIndexedError):
        ledger.index("track-1", 2)
    with pytest.raises(UnknownItemError):
        ledger.index("ghost", 3)


# 10. seq discipline --------------------------------------------------------


def test_seq_discipline():
    ledger = _fresh()
    ledger.hash("a", (0.1,), 0)
    with pytest.raises(SeqOrderError):  # rewind
        ledger.hash("b", (0.1,), 0)
    with pytest.raises(SeqOrderError):  # bool
        ledger.hash("b", (0.1,), True)
    with pytest.raises(SeqOrderError):  # negative
        ledger.hash("b", (0.1,), -1)
    with pytest.raises(SeqOrderError):  # non-int
        ledger.hash("b", (0.1,), "1")
    # malformed seq raises bare, no rejected row
    rows = len(ledger.audit_log())
    with pytest.raises(SeqOrderError):
        ledger.hash("b", (0.1,), -5)
    assert len(ledger.audit_log()) == rows


# 11. audit shapes + leak ban + bad-kind ------------------------------------


def test_audit_shapes_and_leak_ban():
    ledger = _fresh()
    rec = ledger.hash("track-1", (0.1, 0.2), 0)
    ledger.match(rec.fingerprint_id, (0.1, 0.2), 1)
    ledger.index("track-1", 2)
    kinds = [row["kind"] for row in ledger.audit_log()]
    assert kinds == [
        "fingerprinting.hashed",
        "fingerprinting.matched",
        "fingerprinting.indexed",
    ]
    for row in ledger.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        for banned in ("features", "candidate", "vector", "raw", "payload", "value", "text"):
            assert banned not in row["detail"]
    # builder rejects banned keys directly
    with pytest.raises(Exception):
        fingerprinting_audit_event("fingerprinting.hashed", {"features": (0.1,)}, 3)
    with pytest.raises(AuditKindError):
        fingerprinting_audit_event("nope", {}, 3)


# 12. cross-instance determinism -------------------------------------------


def test_cross_instance_determinism():
    a = _fresh()
    b = _fresh()
    ra = a.hash("item", (0.5, -0.25, 0.75), 0)
    rb = b.hash("item", (0.5, -0.25, 0.75), 0)
    assert ra.feature_digest == rb.feature_digest
    ma = a.match(ra.fingerprint_id, (0.5, -0.25, 0.75), 1)
    mb = b.match(rb.fingerprint_id, (0.5, -0.25, 0.75), 1)
    assert ma.digest == mb.digest
    assert ma.distance == mb.distance


# 13. stats + views ----------------------------------------------------------


def test_stats_and_views():
    ledger = _fresh()
    assert ledger.stats()["fingerprints"] == 0
    rec = ledger.hash("t1", (0.1,), 0)
    ledger.index("t1", 1)
    stats = ledger.stats()
    assert stats["fingerprints"] == 1
    assert stats["indexed"] == 1
    assert stats["audit_rows"] == 2
    assert stats["last_seq"] == 1
    with pytest.raises(UnknownItemError):
        ledger.fingerprint("fp-99")
    with pytest.raises(UnknownItemError):
        ledger.fingerprint_id_for("ghost")


# 14. concurrency smoke ------------------------------------------------------


def test_concurrency_smoke():
    ledger = _fresh()
    errors: list = []

    def worker(n: int):
        try:
            ledger.hash(f"item-{n}", (0.1 * n,), 0 + n)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ledger.item_ids()) == 8
    assert all(isinstance(e, SeqOrderError) or isinstance(e, DuplicateItemError) for e in errors) or not errors


# 15. main() subprocess ------------------------------------------------------


def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, "fingerprinting.py"],
        cwd=HERE.parent,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "fingerprinting OK: hash, match, index, pins, audit" in result.stdout
