"""Tests for the ai-transparency disclosure decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_transparency.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_transparency", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_transparency"] = module
    spec.loader.exec_module(module)
    return module


tr = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert tr.AI_TRANSPARENCY_VERSION == "ai-transparency.v1"
    assert tr.SCHEMA_PIN == "northstar.ai-transparency.v1"
    assert tr.DISCLOSURE_KINDS == (
        "model-card",
        "datasheet",
        "system-card",
        "training-disclosure",
        "data-provenance",
        "capability-disclosure",
        "limitation-disclosure",
        "incident-disclosure",
    )
    assert tr.DISCLOSE_VERDICTS == (
        "disclosed",
        "partially-disclosed",
        "undisclosed",
        "inconclusive",
        "not-assessed",
    )
    assert tr.VERIFY_VERDICTS == ("verified", "tampered")
    assert tr.POSTURES == (
        "unassessed",
        "opaque",
        "partial",
        "inconclusive",
        "transparent",
    )
    assert tr.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert tr.AUDIT_KINDS == ("disclosed", "retired", "rejected")


# 2. stdlib-only AST self-check
def test_stdlib_only():
    assert tr.stdlib_only() is True
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    tree = ast.parse(MOD.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or node.module.split(".")[0] in allowed


# 3. disclose roundtrip / dcl-N minting / record verify() / frozen-ness
def test_disclose_roundtrip_minting_verify_frozen():
    led = tr.AITransparency()
    rec = led.disclose("sys-1", 1, disclosure_kind="model-card", verdict="disclosed")
    assert rec.disclosure_id == "dcl-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.verify() is True
    assert rec.digest.startswith("sha256:")
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "undisclosed"  # type: ignore
    rec2 = led.disclose("sys-1", 2, disclosure_kind="datasheet", verdict="disclosed")
    assert rec2.disclosure_id == "dcl-2"
    rec3 = led.disclose("sys-1", 3, disclosure_digest=PIN)
    assert rec3.disclosure_digest == PIN


# 4. disclose bad-input table + seq-burn + rejected-row accounting
def test_disclose_bad_inputs_burn_seq_and_book_rejected():
    led = tr.AITransparency()
    bads = [
        (lambda: led.disclose("", 1), tr.BadSystemError),
        (lambda: led.disclose("   ", 2), tr.BadSystemError),
        (lambda: led.disclose(True, 3), tr.BadSystemError),
        (lambda: led.disclose("sys", 4, disclosure_kind="nope"), tr.BadDisclosureKindError),
        (lambda: led.disclose("sys", 5, verdict="nope"), tr.BadVerdictError),
        (lambda: led.disclose("sys", 6, disclosure_digest="raw"), tr.BadDigestError),
        (lambda: led.disclose("sys", 7, disclosure_digest="sha256:ZZ"), tr.BadDigestError),
    ]
    for thunk, exc in bads:
        with pytest.raises(exc):
            thunk()
    rows = led.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == len(bads)
    assert all(r["details"]["rejected_kind"].endswith("Error") for r in rejected)
    # seq was consumed by the failures; the next good call must keep increasing
    rec = led.disclose("sys", 8, disclosure_kind="model-card", verdict="disclosed")
    assert rec.seq == 8
    # bare rewind raises without consuming or booking
    n_before = len(led.audit_log(0))
    with pytest.raises(tr.SeqOrderError):
        led.disclose("sys", 8)
    assert len(led.audit_log(0)) == n_before
    # malformed seqs never burn
    for bad in (True, 0.5, "9", None):
        with pytest.raises(tr.SeqOrderError):
            led.disclose("sys", bad)
    assert len(led.audit_log(0)) == n_before


# 5. full 8-kind disclosure vocabulary acceptance
def test_full_disclosure_kind_vocabulary():
    led = tr.AITransparency()
    for i, kind in enumerate(tr.DISCLOSURE_KINDS, start=1):
        rec = led.disclose(
            "sys-v", i, disclosure_kind=kind, verdict="disclosed"
        )
        assert rec.verify() is True
    ev = led.evaluate("sys-v", len(tr.DISCLOSURE_KINDS) + 1)
    assert ev.n_disclosures == 8
    assert ev.posture == "transparent"


# 6. full 5-verdict vocabulary acceptance
def test_full_verdict_vocabulary():
    led = tr.AITransparency()
    ids = []
    for i, verdict in enumerate(tr.DISCLOSE_VERDICTS, start=1):
        rec = led.disclose(
            "sys-w", i, disclosure_kind="model-card", verdict=verdict
        )
        ids.append(rec.disclosure_id)
        assert rec.verify() is True
    ev = led.evaluate("sys-w", 6)
    assert ev.n_disclosed == 1
    assert ev.n_partial == 1
    assert ev.n_undisclosed == 1
    assert ev.n_inconclusive == 1
    assert ev.n_not_assessed == 1


# 7. ledger verify() semantics: roundtrip, tamper-as-data, read purity, unknown
def test_ledger_verify_semantics():
    led = tr.AITransparency()
    rec = led.disclose("sys-1", 1, disclosure_kind="datasheet", verdict="disclosed")
    rep = led.verify(rec.disclosure_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # read purity: same seq twice, no audit rows written, no seq consumption
    n_before = len(led.audit_log(0))
    rep2 = led.verify(rec.disclosure_id, 2)
    assert rep2.verdict == "verified"
    assert len(led.audit_log(0)) == n_before
    # unknown disclosure refuses
    with pytest.raises(tr.UnknownDisclosureError):
        led.verify("dcl-999", 3)
    # tamper is reported as data, never raised
    object.__setattr__(rec, "verdict", "undisclosed")
    rep3 = led.verify(rec.disclosure_id, 4)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    assert rep3.verify() is True  # the report itself is digest-pinned


# 8. evaluate posture math: all postures + precedence
def test_evaluate_posture_math():
    led = tr.AITransparency()
    # all disclosed -> transparent
    led.disclose("a", 1, disclosure_kind="model-card", verdict="disclosed")
    led.disclose("a", 2, disclosure_kind="datasheet", verdict="disclosed")
    assert led.evaluate("a", 3).posture == "transparent"
    # any undisclosed -> opaque (outranks partial/inconclusive)
    led.disclose("b", 4, disclosure_kind="model-card", verdict="partially-disclosed")
    led.disclose("b", 5, disclosure_kind="datasheet", verdict="inconclusive")
    led.disclose("b", 6, disclosure_kind="system-card", verdict="undisclosed")
    assert led.evaluate("b", 7).posture == "opaque"
    # partial outranks inconclusive
    led.disclose("c", 8, disclosure_kind="model-card", verdict="partially-disclosed")
    led.disclose("c", 9, disclosure_kind="datasheet", verdict="inconclusive")
    assert led.evaluate("c", 10).posture == "partial"
    # all inconclusive -> inconclusive
    led.disclose("d", 11, disclosure_kind="model-card", verdict="inconclusive")
    assert led.evaluate("d", 12).posture == "inconclusive"
    # only not-assessed -> unassessed
    led.disclose("e", 13, disclosure_kind="model-card", verdict="not-assessed")
    assert led.evaluate("e", 14).posture == "unassessed"


# 9. evaluate read purity + unknown-system refusal
def test_evaluate_read_purity_and_unknown_system():
    led = tr.AITransparency()
    rec = led.disclose("sys-1", 1, disclosure_kind="model-card", verdict="disclosed")
    ev1 = led.evaluate("sys-1", 2)
    ev2 = led.evaluate("sys-1", 2)
    assert ev1 == ev2
    assert ev1.verify() is True
    n_before = len(led.audit_log(0))
    led.evaluate("sys-1", 2)
    assert len(led.audit_log(0)) == n_before
    with pytest.raises(tr.UnknownSystemError):
        led.evaluate("nope", 3)


# 10. retire terminality: bad reason, double-retire, id non-recycling, reads work
def test_retire_terminality():
    led = tr.AITransparency()
    led.disclose("sys-1", 1, disclosure_kind="model-card", verdict="disclosed")
    with pytest.raises(tr.BadReasonError):
        led.retire("sys-1", 2, reason="nope")
    ret = led.retire("sys-1", 3, reason="decommissioned")
    assert ret.verify() is True
    # double retire refused
    with pytest.raises(tr.RetiredSystemError):
        led.retire("sys-1", 4)
    # post-retire mutations refused, ids never recycled
    with pytest.raises(tr.RetiredSystemError):
        led.disclose("sys-1", 5, disclosure_kind="model-card", verdict="disclosed")
    # reads still work post-retire
    ev = led.evaluate("sys-1", 6)
    assert ev.posture == "transparent"
    assert led.disclosure_ids(6) == ("dcl-1",)
    assert led.retired_ids(6) == ("sys-1",)
    # all four reasons accepted on fresh systems
    for i, reason in enumerate(tr.RETIRE_REASONS, start=7):
        r = led.retire(f"sys-r{i}", i)
        assert r.reason == "manual"
    r2 = led.retire("sys-r99", 99, reason="superseded")
    assert r2.reason == "superseded"
    r3 = led.retire("sys-r100", 100, reason="false-start")
    assert r3.reason == "false-start"


# 11. seq discipline: genesis rewind bare, gaps allowed, burn on failure
def test_seq_discipline():
    led = tr.AITransparency()
    with pytest.raises(tr.SeqOrderError):
        led.disclose("sys", 0)  # rewind at genesis is bare, no row
    assert len(led.audit_log(0)) == 0
    rec = led.disclose("sys", 5)  # seq gaps are allowed
    assert rec.seq == 5
    with pytest.raises(tr.BadVerdictError):
        led.disclose("sys", 6, verdict="nope")  # failure burns seq 6
    rec2 = led.disclose("sys", 7)
    assert rec2.seq == 7
    rows = led.audit_log(0)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 1


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_leak_ban_bad_kind():
    led = tr.AITransparency()
    rec = led.disclose("sys-1", 1, disclosure_kind="model-card", verdict="disclosed")
    led.retire("sys-1", 2)
    rows = led.audit_log(0)
    assert [r["kind"] for r in rows] == ["disclosed", "retired"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-transparency"
        assert r["version"] == "ai-transparency.v1"
    disclosed_row = rows[0]
    assert disclosed_row["details"]["disclosure_id"] == rec.disclosure_id
    assert disclosed_row["details"]["disclosure_kind"] == "model-card"
    # banned raw keys raise at the builder
    for key in ("transcript", "weights", "prompt", "evidence", "finding"):
        with pytest.raises(tr.AITransparencyError):
            tr.ai_transparency_audit_event("disclosed", 9, **{key: "raw"})
    # bad kind raises
    with pytest.raises(tr.AuditKindError):
        tr.ai_transparency_audit_event("nope", 9)
    with pytest.raises(tr.SeqOrderError):
        tr.ai_transparency_audit_event("disclosed", True)


# 13. cross-instance digest determinism + tamper flips integrity_ok as data
def test_cross_instance_digest_determinism_and_integrity_flip():
    a = tr.AITransparency()
    b = tr.AITransparency()
    ra = a.disclose("sys", 1, disclosure_kind="model-card", verdict="disclosed")
    rb = b.disclose("sys", 1, disclosure_kind="model-card", verdict="disclosed")
    assert ra.digest == rb.digest
    ea = a.evaluate("sys", 2)
    assert ea.integrity_ok is True
    object.__setattr__(ra, "disclosure_kind", "datasheet")
    assert ra.verify() is False
    ea2 = a.evaluate("sys", 3)
    assert ea2.integrity_ok is False  # tamper flips integrity as data
    assert ea2.posture == "transparent"  # posture itself is declared data too


# 14. views/stats + unknown lookups + 8-thread read smoke
def test_views_stats_and_concurrent_reads():
    led = tr.AITransparency()
    rec = led.disclose("sys-1", 1, disclosure_kind="model-card", verdict="disclosed")
    led.disclose("sys-1", 2, disclosure_kind="datasheet", verdict="partially-disclosed")
    led.disclose("sys-2", 3, disclosure_kind="system-card", verdict="disclosed")
    assert led.disclosure_record(rec.disclosure_id, 4) == rec
    with pytest.raises(tr.UnknownDisclosureError):
        led.disclosure_record("dcl-999", 4)
    assert len(led.disclosures_for("sys-1", 4)) == 2
    assert led.disclosures_for("ghost", 4) == ()
    assert led.system_ids(4) == ("sys-1", "sys-2")
    assert led.disclosure_ids(4) == ("dcl-1", "dcl-2", "dcl-3")
    assert led.retired_ids(4) == ()
    stats = led.stats(4)
    assert stats["systems"] == 2
    assert stats["disclosures"] == 3
    assert stats["retired"] == 0
    assert stats["seq"] == 3
    assert stats["module"] == "ai-transparency.v1"

    errors = []

    def _reader():
        try:
            for _ in range(50):
                assert led.evaluate("sys-1", 4).posture == "partial"
                assert len(led.disclosures_for("sys-2", 4)) == 1
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=_reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "ai-transparency OK: disclose, verify, evaluate, retire, pins, audit" in proc.stdout
