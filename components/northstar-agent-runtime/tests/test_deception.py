"""Tests for the deception (honeypot) operations ledger, Simulated."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "deception.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("deception", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["deception"] = module
    spec.loader.exec_module(module)
    return module


dc = _load()


# 1. version/schema pins
def test_version_and_schema_pins():
    assert dc.DECEPTION_VERSION == "deception.v1"
    assert dc.SCHEMA_PIN == "northstar.deception.v1"
    assert dc.KINDS == (
        "fake-service",
        "honey-token",
        "decoy-document",
        "darknet",
        "honey-account",
        "decoy-api",
    )
    assert dc.INTERACTION_KINDS == (
        "probe",
        "brute-force",
        "scan",
        "payload",
        "lateral",
        "exfiltrate-attempt",
    )
    assert dc.RETIRE_REASONS == ("manual", "burned", "completed", "superseded")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed


# 3. deploy roundtrip + verify()
def test_deploy_roundtrip():
    d = dc.Deception()
    rec = d.deploy("decoy-1", "fake-service", 1, config_digest=PIN)
    assert rec.decoy_id == "decoy-1"
    assert rec.kind == "fake-service"
    assert rec.config_digest == PIN
    assert rec.verify()
    assert d.deployment_record("decoy-1", 0).verify()
    assert d.decoy_ids(0) == ("decoy-1",)


# 4. deploy bad inputs + duplicate + retired + seq burn
def test_deploy_bad_inputs():
    d = dc.Deception()
    d.deploy("d1", "honey-token", 1, config_digest=PIN)
    with pytest.raises(dc.DuplicateDecoyError):
        d.deploy("d1", "honey-token", 2, config_digest=PIN)
    for bad_id in ("", None, 123, "x" * 129):
        g = dc.Deception()
        with pytest.raises(dc.BadDecoyError):
            g.deploy(bad_id, "honey-token", 1, config_digest=PIN)
    g = dc.Deception()
    with pytest.raises(dc.BadKindError):
        g.deploy("d2", "nuke", 1, config_digest=PIN)
    g = dc.Deception()
    with pytest.raises(dc.BadDigestError):
        g.deploy("d2", "honey-token", 1, config_digest="not-a-pin")
    # rejected row booked and seq consumed on the failure
    rows = g.audit_log(0)
    assert any(r["kind"] == "rejected" for r in rows)


# 5. lure roundtrip across all interaction kinds + minted ids
def test_lure_roundtrip_all_kinds():
    d = dc.Deception()
    d.deploy("d", "decoy-api", 1, config_digest=PIN)
    seq = 2
    for i, kind in enumerate(dc.INTERACTION_KINDS):
        rec = d.lure("d", PIN2, seq, interaction_kind=kind)
        assert rec.interaction_id == f"int-{i + 1}"
        assert rec.decoy_id == "d"
        assert rec.interaction_kind == kind
        assert rec.verify()
        seq += 1
    assert len(d.interaction_ids(0)) == 6
    assert d.interactions_for("d", 0) == tuple(f"int-{i + 1}" for i in range(6))


# 6. lure bad inputs: unknown decoy, bad digest, bad kind, retired decoy
def test_lure_bad_inputs():
    d = dc.Deception()
    d.deploy("d", "darknet", 1, config_digest=PIN)
    with pytest.raises(dc.UnknownDecoyError):
        d.lure("nope", PIN2, 2, interaction_kind="probe")
    with pytest.raises(dc.BadDigestError):
        d.lure("d", "raw-actor", 3, interaction_kind="probe")
    with pytest.raises(dc.BadKindError):
        d.lure("d", PIN2, 4, interaction_kind="phishing")
    d.retire("d", 5, reason="burned")
    with pytest.raises(dc.RetiredDecoyError):
        d.lure("d", PIN2, 6, interaction_kind="probe")
    rows = d.audit_log(0)
    assert sum(1 for r in rows if r["kind"] == "rejected") >= 4


# 7. analyze math: tallies, unique actors, engagement verdict
def test_analyze_math():
    d = dc.Deception()
    d.deploy("d", "honey-account", 1, config_digest=PIN)
    d.lure("d", PIN2, 2, interaction_kind="scan")
    d.lure("d", PIN2, 3, interaction_kind="scan")
    d.lure("d", PIN3, 4, interaction_kind="brute-force")
    report = d.analyze("d", 0)
    assert report.verify()
    assert report.n_interactions == 3
    assert report.n_actors == 2
    assert report.engaged is True
    tally = dict(report.interaction_tally)
    assert tally == {"scan": "2", "brute-force": "1"}


# 8. analyze idle decoy + unknown decoy + read purity
def test_analyze_idle_and_pure_read():
    d = dc.Deception()
    d.deploy("d", "decoy-document", 1, config_digest=PIN)
    report = d.analyze("d", 0)
    assert report.verify()
    assert report.engaged is False
    assert report.n_interactions == 0
    assert report.n_actors == 0
    # same seq twice, no audit rows written, seq not consumed
    before = d.audit_log(0)
    d.analyze("d", 0)
    assert d.audit_log(0) == before
    with pytest.raises(dc.UnknownDecoyError):
        d.analyze("nope", 0)


# 9. retire terminality + all reasons + id never recycled
def test_retire_terminality():
    d = dc.Deception()
    d.deploy("d", "fake-service", 1, config_digest=PIN)
    rec = d.retire("d", 2, reason="completed")
    assert rec.verify()
    assert d.retired_ids(0) == ("d",)
    with pytest.raises(dc.RetiredDecoyError):
        d.retire("d", 3, reason="manual")
    with pytest.raises(dc.RetiredDecoyError):
        d.deploy("d", "fake-service", 4, config_digest=PIN)
    with pytest.raises(dc.RetiredDecoyError):
        d.lure("d", PIN2, 5, interaction_kind="probe")
    # analyze still works post-retire (reads are not mutations)
    report = d.analyze("d", 0)
    assert report.verify()


# 10. retire bad reason + unknown decoy + seq burn
def test_retire_bad_inputs():
    d = dc.Deception()
    d.deploy("d", "fake-service", 1, config_digest=PIN)
    with pytest.raises(dc.BadReasonError):
        d.retire("d", 2, reason="vibes")
    with pytest.raises(dc.UnknownDecoyError):
        d.retire("nope", 3, reason="manual")
    rows = d.audit_log(0)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 2


# 11. seq discipline: rewind bare, malformed seqs, failed mutation consumes
def test_seq_discipline():
    d = dc.Deception()
    d.deploy("d", "fake-service", 1, config_digest=PIN)
    with pytest.raises(dc.SeqOrderError):
        d.deploy("d2", "fake-service", 1, config_digest=PIN)  # rewind
    assert d.audit_log(0) and not any(
        r["kind"] == "rejected" and r["seq"] == 1 for r in d.audit_log(0)
        if r["seq"] == 1 and r["kind"] != "deployed"
    )
    for bad_seq in (True, "2", -1, 0.5, None):
        with pytest.raises(dc.SeqOrderError):
            d.deploy("dx", "fake-service", bad_seq, config_digest=PIN)
    # failed mutation consumes its seq
    with pytest.raises(dc.BadKindError):
        d.deploy("dx", "nuke", 2, config_digest=PIN)
    with pytest.raises(dc.SeqOrderError):
        d.deploy("dx", "fake-service", 2, config_digest=PIN)


# 12. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    d = dc.Deception()
    d.deploy("d", "honey-token", 1, config_digest=PIN)
    d.lure("d", PIN2, 2, interaction_kind="payload")
    d.retire("d", 3, reason="burned")
    rows = d.audit_log(0)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["deployed", "interaction-recorded", "retired"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in dc._BANNED_AUDIT_KEYS
    # builder-level bans
    with pytest.raises(dc.AuditKindError):
        dc.deception_audit_event("nope", 0)
    with pytest.raises(dc.AuditKindError):
        dc.deception_audit_event("deployed", 0, payload="raw-material")
    with pytest.raises(dc.SeqOrderError):
        dc.deception_audit_event("deployed", -1)


# 13. cross-instance digest determinism + tamper breaks verify
def test_digest_determinism_and_tamper():
    a = dc.Deception()
    b = dc.Deception()
    ra = a.deploy("d", "fake-service", 1, config_digest=PIN)
    rb = b.deploy("d", "fake-service", 1, config_digest=PIN)
    assert ra.digest == rb.digest
    ia = a.lure("d", PIN2, 2, interaction_kind="probe")
    ib = b.lure("d", PIN2, 2, interaction_kind="probe")
    assert ia.digest == ib.digest
    object.__setattr__(ra, "kind", "darknet")
    assert not ra.verify()
    rep = a.analyze("d", 0)
    assert rep.verify()  # report itself is self-consistent
    assert rep.integrity_ok is False  # tamper reported as data


# 14. frozen records + thread read smoke
def test_frozen_and_concurrent_reads():
    d = dc.Deception()
    d.deploy("d", "fake-service", 1, config_digest=PIN)
    rec = d.deployment_record("d", 0)
    with pytest.raises(Exception):
        rec.decoy_id = "mutated"
    d.lure("d", PIN2, 2, interaction_kind="scan")
    errors = []
    def reader():
        try:
            for _ in range(50):
                assert d.analyze("d", 0).n_interactions == 1
                assert d.stats(0)["decoys"] == 1
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    st = d.stats(0)
    assert st == {"decoys": 1, "interactions": 1, "retired": 0,
                  "audit_rows": 2}


# 15. main() subprocess check + standalone import
def test_main_subprocess():
    r = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=60
    )
    assert r.returncode == 0, r.stderr
    assert "deception OK: deploy, lure, analyze, retire, pins, audit" in r.stdout
