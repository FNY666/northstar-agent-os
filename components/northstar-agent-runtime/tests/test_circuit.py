"""15 tests for circuit.py."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "circuit.py"


def _load():
    spec = importlib.util.spec_from_file_location("circuit", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["circuit"] = mod  # frozen dataclasses need this
    spec.loader.exec_module(mod)
    return mod


ckt_mod = _load()

PIN = "sha256:" + "a" * 64


def _ckt():
    return ckt_mod.Circuit()


# 1. version/schema pins
def test_pins():
    assert ckt_mod.CIRCUIT_VERSION == "circuit.v1"
    assert ckt_mod.SCHEMA_PIN == "northstar.circuit.v1"
    assert set(ckt_mod.CIRCUIT_KINDS) == {
        "feature-circuit", "induction-circuit", "attention-circuit",
        "mlp-circuit", "residual-circuit", "copy-circuit",
    }
    assert set(ckt_mod.VERIFY_METHODS) == {
        "ablation", "patching", "intervention", "correlational",
        "counterfactual",
    }
    assert set(ckt_mod.VERDICTS) == {
        "verified", "partially-verified", "refuted", "inconclusive",
    }
    assert set(ckt_mod.ABLATION_KINDS) == {
        "zero", "mean", "resample", "noise", "path-patch",
    }
    assert set(ckt_mod.EFFECTS) == {
        "degraded", "unchanged", "improved", "crashed",
    }
    assert set(ckt_mod.POSTURES) == {
        "undiscovered", "verified", "refuted", "partially-verified",
        "inconclusive", "unverified",
    }


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD_PATH.read_text())
    allowed = {"__future__", "threading", "dataclasses", "hashlib",
               "json", "typing", "canonical_json", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] in allowed
    assert ckt_mod.Circuit.stdlib_only()


# 3. discover roundtrip + verify + frozen-ness
def test_discover_roundtrip():
    c = _ckt()
    d = c.discover("m1", 1, circuit_kind="induction-circuit",
                   component_digest=PIN, hypothesis_digest=PIN)
    assert d.verify() and d.discovery_id == "ckt-1"
    assert d.model_id == "m1" and d.circuit_kind == "induction-circuit"
    assert d.seq == 1 and d.digest.startswith("sha256:")
    assert c.discovery_record("ckt-1", 2).verify()
    with pytest.raises(Exception):
        d.circuit_kind = "feature-circuit"  # frozen


# 4. discover bad inputs + seq-burn + rejected rows
def test_discover_bad_inputs():
    c = _ckt()
    seq = 0
    bad = [
        (lambda q: c.discover("", q), ckt_mod.BadIdError),
        (lambda q: c.discover("m", q, circuit_kind="vibes"), ckt_mod.BadKindError),
        (lambda q: c.discover("m", q, component_digest="raw-bytes"), ckt_mod.BadDigestError),
        (lambda q: c.discover("m", q, hypothesis_digest="md5:abc"), ckt_mod.BadDigestError),
        (lambda q: c.discover("m" * 200, q), ckt_mod.BadIdError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert c.stats(seq + 1)["rejected"] == len(bad)
    assert len(c.audit_log(seq + 1)) == len(bad)


# 5. all circuit kinds acceptance
def test_all_circuit_kinds():
    c = _ckt()
    seq = 0
    for kind in ckt_mod.CIRCUIT_KINDS:
        seq += 1
        d = c.discover("m1", seq, circuit_kind=kind)
        assert d.verify() and d.discovery_id == f"ckt-{seq}"
    assert len(c.discoveries_for("m1", seq + 1)) == len(ckt_mod.CIRCUIT_KINDS)


# 6. verify roundtrip + full method/verdict vocabulary
def test_verify_roundtrip():
    c = _ckt()
    d = c.discover("m1", 1)
    for i, method in enumerate(ckt_mod.VERIFY_METHODS):
        v = c.verify(d.discovery_id, i + 2, method=method,
                     verdict=ckt_mod.VERDICTS[i % len(ckt_mod.VERDICTS)],
                     evidence_digest=PIN)
        assert v.verify() and v.verification_id == f"vfy-{i + 1}"
        assert v.circuit_id == d.discovery_id
    assert len(ckt_mod.VERIFY_METHODS) == 5 and len(ckt_mod.VERDICTS) == 4
    # full verdict vocabulary also accepted on the last method
    for j, verdict in enumerate(ckt_mod.VERDICTS):
        v = c.verify(d.discovery_id, 7 + j, method="counterfactual",
                     verdict=verdict)
        assert v.verify()
    assert len(c.verifications_for(d.discovery_id, 11)) == 9


# 7. verify bad inputs + seq-burn
def test_verify_bad_inputs():
    c = _ckt()
    d = c.discover("m1", 1)
    seq = 1
    bad = [
        (lambda q: c.verify("ckt-999", q), ckt_mod.UnknownRecordError),
        (lambda q: c.verify(d.discovery_id, q, method="vibes"), ckt_mod.BadMethodError),
        (lambda q: c.verify(d.discovery_id, q, verdict="vibes"), ckt_mod.BadVerdictError),
        (lambda q: c.verify(d.discovery_id, q, evidence_digest="raw"), ckt_mod.BadDigestError),
        (lambda q: c.verify("", q), ckt_mod.BadIdError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert c.stats(seq + 1)["rejected"] == len(bad)


# 8. ablate roundtrip + full vocabulary + chain
def test_ablate_roundtrip():
    c = _ckt()
    d = c.discover("m1", 1)
    for i, kind in enumerate(ckt_mod.ABLATION_KINDS):
        a = c.ablate(d.discovery_id, i + 2, ablation_kind=kind,
                     effect=ckt_mod.EFFECTS[i % len(ckt_mod.EFFECTS)],
                     ablation_digest=PIN)
        assert a.verify() and a.ablation_id == f"abl-{i + 1}"
    assert len(ckt_mod.ABLATION_KINDS) == 5 and len(ckt_mod.EFFECTS) == 4
    # all 5 ablation kinds accepted; chainable: repeat kind on same circuit
    a6 = c.ablate(d.discovery_id, 7, ablation_kind="zero", effect="degraded")
    assert a6.verify() and a6.ablation_id == "abl-6"
    assert len(c.ablations_for(d.discovery_id, 8)) == 6


# 9. ablate bad inputs + seq-burn
def test_ablate_bad_inputs():
    c = _ckt()
    d = c.discover("m1", 1)
    seq = 1
    bad = [
        (lambda q: c.ablate("ckt-999", q), ckt_mod.UnknownRecordError),
        (lambda q: c.ablate(d.discovery_id, q, ablation_kind="vibes"), ckt_mod.BadAblationError),
        (lambda q: c.ablate(d.discovery_id, q, effect="vibes"), ckt_mod.BadEffectError),
        (lambda q: c.ablate(d.discovery_id, q, ablation_digest="raw"), ckt_mod.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert c.stats(seq + 1)["rejected"] == len(bad)


# 10. seq discipline: rewind bare, malformed, burn accounting
def test_seq_discipline():
    c = _ckt()
    c.discover("m1", 1)
    with pytest.raises(ckt_mod.SeqOrderError):
        c.discover("m1", 1)  # rewind: bare, no rejected row
    assert c.stats(2)["rejected"] == 0
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(ckt_mod.SeqOrderError):
            c.discover("m1", bad)
    c.discover("m2", 3)
    # failed mutation consumes its seq + books a rejected row
    with pytest.raises(ckt_mod.BadKindError):
        c.discover("m2", 4, circuit_kind="vibes")
    assert c.stats(5)["rejected"] == 1
    assert c.stats(5)["seq"] == 4


# 11. report posture math
def test_report_postures():
    c = _ckt()
    r = c.report(1)
    assert r.verify() and r.posture == "undiscovered"
    d1 = c.discover("m1", 2)
    assert c.report(3, "m1").posture == "unverified"
    d2 = c.discover("m2", 4)
    c.verify(d2.discovery_id, 5, verdict="inconclusive")
    assert c.report(6, "m2").posture == "inconclusive"
    d3 = c.discover("m3", 7)
    c.verify(d3.discovery_id, 8, verdict="partially-verified")
    assert c.report(9, "m3").posture == "partially-verified"
    d4 = c.discover("m4", 10)
    c.verify(d4.discovery_id, 11, verdict="refuted")
    assert c.report(12, "m4").posture == "refuted"
    c.verify(d1.discovery_id, 13, verdict="verified")
    assert c.report(14, "m1").posture == "verified"
    # precedence: verified beats refuted on the same model
    c.verify(d1.discovery_id, 15, verdict="refuted")
    assert c.report(16, "m1").posture == "verified"
    with pytest.raises(ckt_mod.UnknownModelError):
        c.report(17, "ghost")
    whole = c.report(18)
    assert whole.n_models == 4 and whole.verify()
    assert dict(whole.verdict_tallies) == {
        "verified": 1, "refuted": 2, "partially-verified": 1,
        "inconclusive": 1,
    }


# 12. view purity and stats
def test_view_purity_and_stats():
    c = _ckt()
    d = c.discover("m1", 1)
    c.verify(d.discovery_id, 2)
    c.ablate(d.discovery_id, 3)
    n_audit = len(c.audit_log(4))
    assert c.model_ids(4) == ("m1",)
    assert c.circuit_ids(4) == ("ckt-1",)
    assert c.discoveries_for("m1", 4) == ("ckt-1",)
    assert c.verifications_for("ckt-1", 4) == ("vfy-1",)
    assert c.ablations_for("ckt-1", 4) == ("abl-1",)
    assert len(c.audit_log(4)) == n_audit  # reads add no rows
    st = c.stats(4)
    assert st == {"models": 1, "discoveries": 1, "verifications": 1,
                  "ablations": 1, "rejected": 0, "audit_rows": 3,
                  "seq": 3}
    with pytest.raises(ckt_mod.SeqOrderError):
        c.model_ids(0)  # read seq must be positive int
    with pytest.raises(ckt_mod.UnknownRecordError):
        c.discovery_record("ckt-999", 4)


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    c = _ckt()
    d = c.discover("m1", 1)
    c.verify(d.discovery_id, 2, method="patching", verdict="verified")
    rows = c.audit_log(3)
    assert [r["kind"] for r in rows] == ["circuit.discovered", "circuit.verified"]
    for row in rows:
        for key in row["details"]:
            assert key not in ckt_mod._BANNED_AUDIT_KEYS
    assert ckt_mod.circuit_audit_event("discovered", {"seq": 1})["kind"] == "circuit.discovered"
    with pytest.raises(ckt_mod.AuditKindError):
        ckt_mod.circuit_audit_event("bogus-kind", {"seq": 1})
    with pytest.raises(ckt_mod.AuditKindError):
        ckt_mod.circuit_audit_event("discovered", {"weights": "0.1"})


# 14. determinism + tamper + frozen-ness + thread smoke
def test_determinism_tamper_threads():
    def build():
        c = _ckt()
        d = c.discover("m1", 1, circuit_kind="attention-circuit")
        v = c.verify(d.discovery_id, 2, method="ablation", verdict="verified")
        a = c.ablate(d.discovery_id, 3, ablation_kind="zero", effect="degraded")
        return c, d, v, a

    c1, d1, v1, a1 = build()
    c2, d2, v2, a2 = build()
    assert d1.digest == d2.digest
    assert v1.digest == v2.digest
    assert a1.digest == a2.digest
    assert c1.report(4, "m1").digest == c2.report(4, "m1").digest
    import dataclasses
    tampered = dataclasses.replace(v1, verdict="refuted")
    assert tampered.verify() is False  # tamper breaks verify()
    with pytest.raises(Exception):
        a1.effect = "crashed"  # frozen
    # 8-thread read smoke
    results = []

    def worker():
        results.append(c1.model_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r == ("m1",) for r in results)


# 15. main() subprocess check
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MOD_PATH)],
        capture_output=True,
        text=True,
        cwd=str(MOD_PATH.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "circuit OK: discover, verify, ablate, report, pins, audit"
    )
