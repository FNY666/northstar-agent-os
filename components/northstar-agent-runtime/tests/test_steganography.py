"""Tests for steganography.py — hidden-message bookkeeping ledger."""

from __future__ import annotations

import ast
import hashlib
import importlib
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, ".")

import steganography  # noqa: E402
from steganography import (  # noqa: E402
    AUDIT_KINDS,
    DETECT_VERDICTS,
    EXTRACT_OUTCOMES,
    SCHEMA,
    TECHNIQUES,
    VERSION,
    AuditKindError,
    BadDigestError,
    BadIdError,
    BadScoreError,
    BadTechniqueError,
    BadVerdictError,
    DuplicateHideError,
    SeqOrderError,
    Steganography,
    SteganographyError,
    steganography_audit_event,
)


def _pin(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


PIN = _pin("the secret message")
KEY = _pin("shared-secret")
FEAT = _pin("rs-noise-stats")


def fresh() -> Steganography:
    return Steganography()


# ---------------------------------------------------------------------------
# 1. pins
# ---------------------------------------------------------------------------


def test_version_schema_pins():
    assert steganography.VERSION == VERSION == "steganography.v1"
    assert steganography.SCHEMA == SCHEMA == "northstar.steganography.v1"
    assert steganography.AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(TECHNIQUES) == {"lsb", "zero-width", "metadata", "whitespace", "unicode-homoglyph"}
    assert set(EXTRACT_OUTCOMES) == {"recovered", "no-payload", "ambiguous"}
    assert set(DETECT_VERDICTS) == {"clean", "suspicious", "inconclusive"}


# ---------------------------------------------------------------------------
# 2. stdlib-only AST check
# ---------------------------------------------------------------------------


def test_stdlib_only():
    src = open("steganography.py").read()
    tree = ast.parse(src)
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# 3. hide roundtrip
# ---------------------------------------------------------------------------


def test_hide_roundtrip():
    st = fresh()
    rec = st.hide("img-001.png", PIN, 1, technique="lsb", key_digest=KEY)
    assert rec.carrier_id == "img-001.png"
    assert rec.message_digest == PIN
    assert rec.technique == "lsb"
    assert rec.key_digest == KEY
    assert rec.schema == SCHEMA and rec.version == VERSION
    assert rec.verify()
    assert st.hide_record("img-001.png", 1) == rec
    assert st.carrier_ids(1) == ("img-001.png",)


# ---------------------------------------------------------------------------
# 4. raw message refused
# ---------------------------------------------------------------------------


def test_raw_message_refused_seq_burn():
    st = fresh()
    for seq, raw in ((1, "the secret"), (2, b"bytes"), (3, "x")):
        with pytest.raises(BadDigestError):
            st.hide("c", raw, seq)
    rejected = [e for e in st.audit_log(9) if e["kind"] == "steganography.rejected"]
    assert len(rejected) == 3


# ---------------------------------------------------------------------------
# 5. duplicate hide refused
# ---------------------------------------------------------------------------


def test_duplicate_hide_refused():
    st = fresh()
    st.hide("c1", PIN, 1)
    with pytest.raises(DuplicateHideError):
        st.hide("c1", PIN, 2)
    rejected = [e for e in st.audit_log(9) if e["kind"] == "steganography.rejected"]
    assert len(rejected) == 1


# ---------------------------------------------------------------------------
# 6. bad id / technique / digest
# ---------------------------------------------------------------------------


def test_bad_inputs():
    st = fresh()
    bad_cases = [
        ("", PIN, 1, "lsb"),
        ("c" * 129, PIN, 2, "lsb"),
        (123, PIN, 3, "lsb"),
        ("c", "not-a-pin", 4, "lsb"),
        ("c", "sha256:" + "zz" * 32, 5, "lsb"),
        ("c", PIN, 6, "invisible-ink"),
        ("c", PIN, 7, 42),
    ]
    for carrier, digest, seq, tech in bad_cases:
        with pytest.raises(SteganographyError):
            st.hide(carrier, digest, seq, technique=tech)
    rejected = [e for e in st.audit_log(99) if e["kind"] == "steganography.rejected"]
    assert len(rejected) == len(bad_cases)


# ---------------------------------------------------------------------------
# 7. extract semantics
# ---------------------------------------------------------------------------


def test_extract_recovered_and_no_payload():
    st = fresh()
    st.hide("c1", PIN, 1, technique="zero-width")
    got = st.extract("c1", 2)
    assert got.outcome == "recovered"
    assert got.message_digest == PIN
    assert got.verify()
    miss = st.extract("nothing", 3)
    assert miss.outcome == "no-payload"
    assert miss.message_digest == ""
    assert miss.verify()
    assert len(st.extractions_for("c1", 3)) == 1
    assert len(st.extractions_for("nothing", 3)) == 1


# ---------------------------------------------------------------------------
# 8. detect verdicts
# ---------------------------------------------------------------------------


def test_detect_roundtrip():
    st = fresh()
    rep = st.detect("c1", "suspicious", 0.87, 1, features_digest=FEAT)
    assert rep.verdict == "suspicious"
    assert rep.anomaly_score == 0.87
    assert rep.features_digest == FEAT
    assert rep.verify()
    rep2 = st.detect("c2", "clean", 0.0, 2)
    assert rep2.verdict == "clean"
    assert rep2.features_digest == ""
    assert len(st.detections_for("c1", 2)) == 1


# ---------------------------------------------------------------------------
# 9. bad verdict / score
# ---------------------------------------------------------------------------


def test_bad_verdict_score():
    st = fresh()
    with pytest.raises(BadVerdictError):
        st.detect("c", "definitely-stego", 0.5, 1)
    with pytest.raises(BadScoreError):
        st.detect("c", "clean", 1.5, 2)
    with pytest.raises(BadScoreError):
        st.detect("c", "clean", -0.1, 3)
    with pytest.raises(BadScoreError):
        st.detect("c", "clean", float("nan"), 4)
    with pytest.raises(BadScoreError):
        st.detect("c", "clean", True, 5)
    rejected = [e for e in st.audit_log(99) if e["kind"] == "steganography.rejected"]
    assert len(rejected) == 5


# ---------------------------------------------------------------------------
# 10. seq discipline
# ---------------------------------------------------------------------------


def test_seq_discipline():
    st = fresh()
    st.hide("c1", PIN, 1)
    with pytest.raises(SeqOrderError):
        st.hide("c2", PIN, 1)  # rewind
    with pytest.raises(SeqOrderError):
        st.hide("c2", PIN, True)
    with pytest.raises(SeqOrderError):
        st.hide("c2", PIN, "x")
    with pytest.raises(SeqOrderError):
        st.extract("c1", 0)  # below current
    # pure reads at any int seq shape are fine and consume nothing
    st.stats(1)
    st.stats(10**9)
    assert st.stats(1)["hides"] == 1


# ---------------------------------------------------------------------------
# 11. audit shapes + leak ban
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    st = fresh()
    st.hide("c1", PIN, 1)
    st.extract("c1", 2)
    st.detect("c1", "inconclusive", 0.4, 3)
    kinds = [e["kind"] for e in st.audit_log(3)]
    assert kinds == ["message-hidden", "extracted", "detection-reported"]
    for event in st.audit_log(3):
        for banned in ("message", "text", "content", "payload", "raw", "secret"):
            assert banned not in event["detail"]
    with pytest.raises(AuditKindError):
        steganography_audit_event("extracted", 4, carrier_id="x", message="leak")
    with pytest.raises(AuditKindError):
        steganography_audit_event("no-such-kind", 4)


# ---------------------------------------------------------------------------
# 12. cross-instance digest determinism + tamper rejection
# ---------------------------------------------------------------------------


def test_determinism_and_tamper():
    a, b = fresh(), fresh()
    ra = a.hide("c1", PIN, 1, technique="whitespace", key_digest=KEY)
    rb = b.hide("c1", PIN, 1, technique="whitespace", key_digest=KEY)
    assert ra.digest == rb.digest
    ea = a.extract("c1", 2)
    eb = b.extract("c1", 2)
    assert ea.digest == eb.digest
    da = a.detect("c1", "clean", 0.1, 3)
    db = b.detect("c1", "clean", 0.1, 3)
    assert da.digest == db.digest
    import dataclasses

    tampered = dataclasses.replace(ra, technique="lsb")
    assert not tampered.verify()
    tampered2 = dataclasses.replace(ra, message_digest=_pin("other"))
    assert not tampered2.verify()


# ---------------------------------------------------------------------------
# 13. pure-read views
# ---------------------------------------------------------------------------


def test_pure_read_views():
    st = fresh()
    st.hide("c1", PIN, 1)
    st.hide("c2", PIN, 2)
    st.extract("c1", 3)
    before = len(st.audit_log(9))
    assert st.hide_record("c2", 9) is not None
    assert st.hide_record("missing", 9) is None
    assert st.extractions_for("c1", 9)
    assert st.detections_for("c1", 9) == ()
    assert st.carrier_ids(9) == ("c1", "c2")
    s = st.stats(9)
    assert s == {
        "hides": 2,
        "extractions": 1,
        "detections": 0,
        "audit_events": before,
        "schema": SCHEMA,
        "version": VERSION,
    }
    assert len(st.audit_log(9)) == before


# ---------------------------------------------------------------------------
# 14. frozen records + concurrency smoke
# ---------------------------------------------------------------------------


def test_frozen_and_threads():
    st = fresh()
    rec = st.hide("c1", PIN, 1)
    with pytest.raises(Exception):
        rec.technique = "lsb"  # type: ignore
    errors: list = []

    def reader():
        try:
            st.stats(9)
            st.carrier_ids(9)
            st.audit_log(9)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# ---------------------------------------------------------------------------
# 15. main() subprocess check
# ---------------------------------------------------------------------------


def test_main_subprocess():
    r = subprocess.run(
        [sys.executable, "steganography.py"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, r.stderr
    assert "steganography OK: hide, extract, detect, pins, audit" in r.stdout
