"""Tests for the trojan-defense remediation ledger (Simulated)."""

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "trojan_defense.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("trojan_defense", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["trojan_defense"] = module
    spec.loader.exec_module(module)
    return module


td = _load()


# 1. version/schema pins
def test_version_and_schema_pins():
    assert td.TROJAN_DEFENSE_VERSION == "trojan-defense.v1"
    assert td.SCHEMA_PIN == "northstar.trojan-defense.v1"
    assert td.METHODS == (
        "activation-clustering",
        "trigger-inversion",
        "fine-pruning",
        "spectral",
        "weight-analysis",
        "behavioral",
    )
    assert td.VERDICTS == ("clean", "suspect", "infected")
    assert td.TECHNIQUES == (
        "fine-pruning",
        "retrain",
        "weight-repair",
        "rollback",
        "deletion",
    )


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


# 3. register_model roundtrip
def test_register_model_roundtrip():
    t = td.TrojanDefense()
    rec = t.register_model("model-1", 1, model_digest=PIN)
    assert rec.model_id == "model-1"
    assert rec.model_digest == PIN
    assert rec.verify()
    assert t.model_record("model-1", 0).verify()


# 4. register_model bad inputs + duplicate + seq burn
def test_register_model_bad_inputs():
    t = td.TrojanDefense()
    t.register_model("m", 1, model_digest=PIN)
    with pytest.raises(td.DuplicateModelError):
        t.register_model("m", 2, model_digest=PIN)
    for bad_id in ("", None, 123, "x" * 129):
        g = td.TrojanDefense()
        with pytest.raises(td.BadModelError):
            g.register_model(bad_id, 1, model_digest=PIN)
    g = td.TrojanDefense()
    with pytest.raises(td.BadDigestError):
        g.register_model("m", 1, model_digest="not-a-pin")
    # rejected row booked and seq consumed on the failure
    rows = g.audit_log(0)
    assert any(r["kind"] == "rejected" for r in rows)


# 5. scan roundtrip across all methods + minted ids + verify()
def test_scan_roundtrip_all_methods():
    t = td.TrojanDefense()
    t.register_model("m", 1, model_digest=PIN)
    seq = 2
    for i, method in enumerate(td.METHODS):
        rec = t.scan("m", seq, method=method, verdict="infected",
                     findings_digest=PIN2)
        assert rec.scan_id == f"scn-{i + 1}"
        assert rec.method == method
        assert rec.verdict == "infected"
        assert rec.verify()
        seq += 1
    assert len(t.scan_ids(0)) == 6


# 6. scan verdict vocabulary + bad inputs + unknown model + seq burn
def test_scan_bad_inputs():
    t = td.TrojanDefense()
    t.register_model("m", 1, model_digest=PIN)
    with pytest.raises(td.UnknownModelError):
        t.scan("nope", 2)
    with pytest.raises(td.BadMethodError):
        t.scan("m", 3, method="magic")
    with pytest.raises(td.BadVerdictError):
        t.scan("m", 4, verdict="maybe")
    with pytest.raises(td.BadDigestError):
        t.scan("m", 5, findings_digest="raw-text")
    # 4 failures -> 4 rejected rows, seq still advances only forward
    rows = t.audit_log(0)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 4
    rec = t.scan("m", 6)
    assert rec.scan_id == "scn-1"
    assert rec.verdict == "clean"


# 7. quarantine lifecycle + duplicate refusal + unknown model
def test_quarantine_lifecycle():
    t = td.TrojanDefense()
    t.register_model("m", 1, model_digest=PIN)
    q = t.quarantine("m", 2, reason="precaution")
    assert q.model_id == "m"
    assert q.reason == "precaution"
    assert q.verify()
    assert t.is_quarantined("m", 0)
    with pytest.raises(td.QuarantineStateError):
        t.quarantine("m", 3, reason="manual")
    with pytest.raises(td.BadReasonError):
        t.quarantine("m", 4, reason="vibes")
    with pytest.raises(td.UnknownModelError):
        t.quarantine("ghost", 5)


# 8. remove lifecycle (suspect/infected only) + technique vocabulary
def test_remove_lifecycle():
    t = td.TrojanDefense()
    t.register_model("m", 1, model_digest=PIN)
    infected = t.scan("m", 2, verdict="infected", method="trigger-inversion")
    suspect = t.scan("m", 3, verdict="suspect", method="spectral")
    r1 = t.remove("m", infected.scan_id, 4, technique="retrain")
    assert r1.scan_id == infected.scan_id
    assert r1.technique == "retrain"
    assert r1.verify()
    # double removal of the same scan refused
    with pytest.raises(td.RemovalStateError):
        t.remove("m", infected.scan_id, 5)
    # suspect scan remediable with every technique
    seq = 6
    for tech in td.TECHNIQUES:
        if tech == "deletion":
            continue
        t2 = td.TrojanDefense()
        t2.register_model("m2", 1, model_digest=PIN)
        s = t2.scan("m2", 2, verdict="suspect")
        r = t2.remove("m2", s.scan_id, 3, technique=tech)
        assert r.technique == tech and r.verify()
    r2 = t.remove("m", suspect.scan_id, 6, technique="fine-pruning")
    assert r2.verify()


# 9. remove refused on clean verdict + unknown scan + cross-model scan
def test_remove_refusals():
    t = td.TrojanDefense()
    t.register_model("m", 1, model_digest=PIN)
    t.register_model("n", 2, model_digest=PIN)
    clean_scan = t.scan("m", 3, verdict="clean")
    with pytest.raises(td.RemovalStateError):
        t.remove("m", clean_scan.scan_id, 4)
    with pytest.raises(td.UnknownScanError):
        t.remove("m", "scn-999", 5)
    other = t.scan("n", 6, verdict="infected")
    with pytest.raises(td.UnknownScanError):
        t.remove("m", other.scan_id, 7)
    inf2 = t.scan("n", 8, verdict="infected")
    with pytest.raises(td.BadTechniqueError):
        t.remove("n", inf2.scan_id, 9, technique="prayer")
    # deletion retires the model id forever
    inf = t.scan("m", 10, verdict="infected")
    t.remove("m", inf.scan_id, 11, technique="deletion")
    assert t.is_retired("m", 0)
    with pytest.raises(td.RetiredModelError):
        t.register_model("m", 12, model_digest=PIN)


# 10. verify pure read semantics (no seq consumption, no audit rows)
def test_verify_pure_read():
    t = td.TrojanDefense()
    t.register_model("m", 1, model_digest=PIN)
    scan = t.scan("m", 2, verdict="infected")
    before = len(t.audit_log(0))
    r1 = t.verify("m", 0)
    r2 = t.verify("m", 0)
    assert len(t.audit_log(0)) == before
    assert r1.n_scans == 1
    assert r1.latest_verdict == "infected"
    assert not r1.quarantined
    assert not r1.remediated
    assert r1.verify() and r2.verify()
    with pytest.raises(td.UnknownModelError):
        t.verify("ghost", 0)
    with pytest.raises(td.SeqOrderError):
        t.verify("m", -1)
    # after removal, remediated=True
    t.remove("m", scan.scan_id, 3, technique="weight-repair")
    r3 = t.verify("m", 0)
    assert r3.remediated


# 11. seq discipline (rewind bare, malformed, failed-mutation-consumes-seq)
def test_seq_discipline():
    t = td.TrojanDefense()
    t.register_model("m", 1, model_digest=PIN)
    with pytest.raises(td.SeqOrderError):
        t.register_model("n", 1, model_digest=PIN)  # rewind
    for bad in (True, "2", 2.5, None):
        g = td.TrojanDefense()
        with pytest.raises(td.SeqOrderError):
            g.register_model("m", bad, model_digest=PIN)
    # bare rewind raises without booking a rejected row
    g2 = td.TrojanDefense()
    g2.register_model("m", 1, model_digest=PIN)
    before = len(g2.audit_log(0))
    with pytest.raises(td.SeqOrderError):
        g2.scan("m", 1)  # rewind -> bare raise
    assert len(g2.audit_log(0)) == before
    # failed mutation consumes seq and books rejected
    with pytest.raises(td.BadMethodError):
        g2.scan("m", 2, method="nope")
    with pytest.raises(td.SeqOrderError):
        g2.scan("m", 2, method="spectral")  # seq 2 was burned


# 12. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    t = td.TrojanDefense()
    t.register_model("m", 1, model_digest=PIN)
    t.scan("m", 2, verdict="infected")
    for row in t.audit_log(0):
        assert row["schema"] == "audit.ndjson/1"
        assert row["kind"] in td.AUDIT_KINDS
        assert isinstance(row["seq"], int) and row["seq"] >= 0
    with pytest.raises(td.AuditKindError):
        td.trojan_defense_audit_event("nope", 1)
    with pytest.raises(td.AuditKindError):
        td.trojan_defense_audit_event("scan-recorded", 1, weights=b"xx")
    with pytest.raises(td.AuditKindError):
        td.trojan_defense_audit_event("scan-recorded", 1, trigger="cf")
    ev = td.trojan_defense_audit_event(
        "removed", 3, removal_id="rmv-1", model_id="m",
        scan_id="scn-1", technique="retrain")
    assert ev["kind"] == "removed"


# 13. cross-instance digest determinism + tamper rejection
def test_digest_determinism_and_tamper():
    a = td.TrojanDefense()
    b = td.TrojanDefense()
    ra = a.register_model("m", 1, model_digest=PIN)
    rb = b.register_model("m", 1, model_digest=PIN)
    assert ra.digest == rb.digest
    sa = a.scan("m", 2, method="spectral", verdict="suspect",
                findings_digest=PIN2)
    sb = b.scan("m", 2, method="spectral", verdict="suspect",
                findings_digest=PIN2)
    assert sa.digest == sb.digest
    object.__setattr__(sa, "verdict", "clean")
    assert not sa.verify()


# 14. views/stats/frozen-ness
def test_views_stats_and_frozen():
    t = td.TrojanDefense()
    t.register_model("m", 1, model_digest=PIN)
    s = t.scan("m", 2, verdict="clean")
    t.quarantine("m", 3)
    assert t.model_ids(0) == ("m",)
    assert t.scan_ids(0) == ("scn-1",)
    assert t.scans_for("m", 0) == ("scn-1",)
    assert t.quarantined_ids(0) == ("m",)
    assert t.scan_record("scn-1", 0).scan_id == s.scan_id
    stats = t.stats(0)
    assert stats["models"] == 1
    assert stats["scans"] == 1
    assert stats["quarantined"] == 1
    assert stats["audit_rows"] == 3
    import dataclasses
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.verdict = "infected"  # type: ignore
    with pytest.raises(td.UnknownRemovalError):
        t.removal_record("rmv-999", 0)


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    assert "trojan-defense OK" in proc.stdout
