"""Tests for the feature-viz decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "feature_viz.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("feature_viz", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["feature_viz"] = module
    spec.loader.exec_module(module)
    return module


fv = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert fv.FEATURE_VIZ_VERSION == "feature-viz.v1"
    assert fv.SCHEMA_PIN == "northstar.feature-viz.v1"
    assert fv.VIZ_METHODS == (
        "activation-maximization",
        "feature-inversion",
        "gradient-ascent",
        "dataset-examples",
        "caricature",
        "attribution-map",
    )
    assert fv.VIZ_OUTCOMES == (
        "generated",
        "failed",
        "ambiguous",
        "inconclusive",
    )
    assert fv.VERIFICATION_VERDICTS == (
        "consistent",
        "tampered",
    )
    assert fv.COMPARISON_VERDICTS == (
        "identical",
        "similar",
        "different",
        "incomparable",
    )
    assert fv.AUDIT_KINDS == (
        "visualized",
        "compared",
        "rejected",
    )


# 2. stdlib-only AST check
def test_stdlib_only_imports():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "__future__",
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert node.module.split(".")[0] in allowed, node.module


# 3. visualize roundtrip + verify + frozen-ness
def test_visualize_roundtrip():
    f = fv.FeatureViz()
    rec = f.visualize(
        "m-1", 1, method="activation-maximization", outcome="generated",
        feature_digest=PIN, model_digest=PIN2,
    )
    assert rec.viz_id == "viz-1"
    assert rec.model_id == "m-1"
    assert rec.method == "activation-maximization"
    assert rec.outcome == "generated"
    assert rec.feature_digest == PIN
    assert rec.model_digest == PIN2
    assert rec.verify()
    assert rec.as_dict()["schema"] == fv.SCHEMA_PIN
    with pytest.raises(Exception):
        rec.method = "dataset-examples"  # frozen


# 4. visualize bad-input table + seq-burn + rejected-row accounting
def test_visualize_bad_inputs():
    f = fv.FeatureViz()
    seq = 0
    bad = [
        (lambda s: f.visualize("", s, feature_digest=PIN, model_digest=PIN2),
         fv.BadIdError),
        (lambda s: f.visualize(123, s, feature_digest=PIN, model_digest=PIN2),
         fv.BadIdError),
        (lambda s: f.visualize("m-1", s, method="nope",
                               feature_digest=PIN, model_digest=PIN2),
         fv.BadMethodError),
        (lambda s: f.visualize("m-1", s, outcome="nope",
                               feature_digest=PIN, model_digest=PIN2),
         fv.BadOutcomeError),
        (lambda s: f.visualize("m-1", s, feature_digest="raw-bytes",
                               model_digest=PIN2),
         fv.BadDigestError),
        (lambda s: f.visualize("m-1", s, feature_digest="md5:abc",
                               model_digest=PIN2),
         fv.BadDigestError),
        (lambda s: f.visualize("m-1", s, feature_digest=PIN, model_digest=""),
         fv.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert f.stats(seq + 1)["rejected"] == len(bad)
    rows = f.audit_log(seq + 1)
    assert [r["kind"] for r in rows] == ["rejected"] * len(bad)
    assert all(r["schema"] == "audit.ndjson/1" for r in rows)


# 5. full method and outcome vocabulary acceptance
def test_all_methods_and_outcomes():
    f = fv.FeatureViz()
    seq = 0
    for method in fv.VIZ_METHODS:
        seq += 1
        rec = f.visualize(
            "m-1", seq, method=method, outcome="generated",
            feature_digest=PIN, model_digest=PIN2,
        )
        assert rec.method == method
        assert rec.verify()
    for outcome in fv.VIZ_OUTCOMES:
        seq += 1
        rec = f.visualize(
            "m-2", seq, method="caricature", outcome=outcome,
            feature_digest=PIN, model_digest=PIN2,
        )
        assert rec.outcome == outcome
        assert rec.verify()
    assert f.stats(seq + 1)["visualizations"] == len(fv.VIZ_METHODS) + len(fv.VIZ_OUTCOMES)


# 6. verify read purity + unknown refusal
def test_verify_read_purity():
    f = fv.FeatureViz()
    rec = f.visualize("m-1", 1, feature_digest=PIN, model_digest=PIN2)
    n_audit = len(f.audit_log(2))
    rep1 = f.verify(rec.viz_id, 2)
    rep2 = f.verify(rec.viz_id, 2)  # same seq twice: reads consume nothing
    assert rep1.verdict == "consistent"
    assert rep1.integrity_ok is True
    assert rep1.verify()
    assert rep1.as_dict()["verdict"] == "consistent"
    assert len(f.audit_log(2)) == n_audit  # no audit rows from reads
    with pytest.raises(fv.UnknownVisualizationError):
        f.verify("viz-999", 3)  # pure-read refusal burns no seq


# 7. tamper is derived as data, not raised
def test_verify_tamper_as_data():
    f = fv.FeatureViz()
    rec = f.visualize("m-1", 1, feature_digest=PIN, model_digest=PIN2)
    rep = f.verify(rec.viz_id, 2)
    assert rep.verdict == "consistent"
    object.__setattr__(rec, "outcome", "failed")
    assert rec.verify() is False
    rep2 = f.verify(rec.viz_id, 3)
    assert rep2.verdict == "tampered"
    assert rep2.integrity_ok is False
    assert rep2.verify()  # the report itself is intact


# 8. compare roundtrip + minted ids
def test_compare_roundtrip():
    f = fv.FeatureViz()
    v1 = f.visualize("m-1", 1, feature_digest=PIN, model_digest=PIN2)
    v2 = f.visualize("m-1", 2, feature_digest=PIN2, model_digest=PIN2)
    rec = f.compare(v1.viz_id, v2.viz_id, 3, verdict="similar",
                    comparison_digest=PIN3)
    assert rec.comparison_id == "cmp-1"
    assert rec.viz_id_a == v1.viz_id
    assert rec.viz_id_b == v2.viz_id
    assert rec.verdict == "similar"
    assert rec.comparison_digest == PIN3
    assert rec.verify()
    assert rec.as_dict()["schema"] == fv.SCHEMA_PIN
    with pytest.raises(Exception):
        rec.verdict = "identical"  # frozen
    assert f.comparisons_for(v1.viz_id, 4) == ("cmp-1",)
    assert f.comparisons_for(v2.viz_id, 4) == ("cmp-1",)
    assert f.comparison_record("cmp-1", 4).verify()


# 9. compare refusals + seq-burn
def test_compare_refusals():
    f = fv.FeatureViz()
    v1 = f.visualize("m-1", 1, feature_digest=PIN, model_digest=PIN2)
    v2 = f.visualize("m-1", 2, feature_digest=PIN2, model_digest=PIN2)
    seq = 2
    bad = [
        (lambda s: f.compare("viz-999", v2.viz_id, s, comparison_digest=PIN),
         fv.UnknownVisualizationError),
        (lambda s: f.compare(v1.viz_id, "viz-999", s, comparison_digest=PIN),
         fv.UnknownVisualizationError),
        (lambda s: f.compare(v1.viz_id, v1.viz_id, s, comparison_digest=PIN),
         fv.SelfComparisonError),
        (lambda s: f.compare(v1.viz_id, v2.viz_id, s, verdict="nope",
                             comparison_digest=PIN),
         fv.BadVerdictError),
        (lambda s: f.compare(v1.viz_id, v2.viz_id, s, comparison_digest="raw"),
         fv.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert f.stats(seq + 1)["rejected"] == len(bad)


# 10. full comparison-verdict vocabulary
def test_all_comparison_verdicts():
    f = fv.FeatureViz()
    seq = 0
    seq += 1
    v1 = f.visualize("m-1", seq, feature_digest=PIN, model_digest=PIN2)
    seq += 1
    v2 = f.visualize("m-1", seq, feature_digest=PIN2, model_digest=PIN2)
    for verdict in fv.COMPARISON_VERDICTS:
        seq += 1
        rec = f.compare(v1.viz_id, v2.viz_id, seq, verdict=verdict,
                        comparison_digest=PIN3)
        assert rec.verdict == verdict
        assert rec.verify()


# 11. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    f = fv.FeatureViz()
    f.visualize("m-1", 5, feature_digest=PIN, model_digest=PIN2)
    with pytest.raises(fv.SeqOrderError):
        f.visualize("m-2", 5, feature_digest=PIN, model_digest=PIN2)  # rewind: bare
    assert f.stats(6)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(fv.SeqOrderError):
            f.visualize("m-2", bad, feature_digest=PIN, model_digest=PIN2)
    f.visualize("m-2", 7, feature_digest=PIN, model_digest=PIN2)
    assert f.model_ids(8) == ("m-1", "m-2")
    with pytest.raises(fv.SeqOrderError):
        f.visualize("m-3", 6, feature_digest=PIN, model_digest=PIN2)  # rewind: bare


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    f = fv.FeatureViz()
    v1 = f.visualize("m-1", 1, method="gradient-ascent", outcome="generated",
                     feature_digest=PIN, model_digest=PIN2)
    v2 = f.visualize("m-1", 2, method="attribution-map", outcome="ambiguous",
                     feature_digest=PIN2, model_digest=PIN2)
    f.compare(v1.viz_id, v2.viz_id, 3, verdict="different",
              comparison_digest=PIN3)
    rows = f.audit_log(4)
    assert [r["kind"] for r in rows] == ["visualized", "visualized", "compared"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["seq"] in (1, 2, 3)
        for key in row["details"]:
            assert key not in fv._BANNED_AUDIT_KEYS
    with pytest.raises(fv.AuditKindError):
        fv.feature_viz_audit_event("visualized", 1, image="raw-pixels")
    with pytest.raises(fv.AuditKindError):
        fv.feature_viz_audit_event("bogus-kind", 1)
    with pytest.raises(fv.SeqOrderError):
        fv.feature_viz_audit_event("visualized", -1)


# 13. cross-instance digest determinism + tamper breaks verify
def test_determinism_and_tamper():
    def build():
        f = fv.FeatureViz()
        v = f.visualize("m-1", 1, method="dataset-examples", outcome="generated",
                        feature_digest=PIN, model_digest=PIN2)
        v2 = f.visualize("m-2", 2, feature_digest=PIN2, model_digest=PIN2)
        f.compare(v.viz_id, v2.viz_id, 3, verdict="identical",
                  comparison_digest=PIN3)
        return f

    f1, f2 = build(), build()
    assert f1.visualization_record("viz-1", 4).digest == f2.visualization_record("viz-1", 4).digest
    assert f1.comparison_record("cmp-1", 4).digest == f2.comparison_record("cmp-1", 4).digest
    rec = f1.visualization_record("viz-1", 4)
    tampered = dataclasses.replace(rec, method="caricature")
    assert tampered.verify() is False
    object.__setattr__(rec, "method", "caricature")
    assert rec.verify() is False
    rep = f1.verify("viz-1", 5)
    assert rep.verdict == "tampered" and rep.integrity_ok is False


# 14. views/stats + unknown lookups
def test_views_and_stats():
    f = fv.FeatureViz()
    v1 = f.visualize("m-1", 1, feature_digest=PIN, model_digest=PIN2)
    v2 = f.visualize("m-1", 2, feature_digest=PIN2, model_digest=PIN2)
    v3 = f.visualize("m-2", 3, feature_digest=PIN3, model_digest=PIN2)
    f.compare(v1.viz_id, v2.viz_id, 4, verdict="identical",
              comparison_digest=PIN3)
    assert f.visualizations_for("m-1", 5) == (v1.viz_id, v2.viz_id)
    assert f.visualizations_for("m-2", 5) == (v3.viz_id,)
    assert f.comparisons_for(v3.viz_id, 5) == ()
    assert f.model_ids(5) == ("m-1", "m-2")
    assert f.stats(5) == {
        "models": 2,
        "visualizations": 3,
        "comparisons": 1,
        "rejected": 0,
    }
    with pytest.raises(fv.UnknownModelError):
        f.visualizations_for("m-999", 6)
    with pytest.raises(fv.UnknownComparisonError):
        f.comparison_record("cmp-999", 6)
    with pytest.raises(fv.UnknownVisualizationError):
        f.visualization_record("viz-999", 6)


# 15. concurrency smoke + main() subprocess check
def test_concurrency_and_main():
    f = fv.FeatureViz()
    for i in range(10):
        mid = f"m{i}"
        f.visualize(mid, i * 2 + 1, method=fv.VIZ_METHODS[i % 6],
                    feature_digest=PIN, model_digest=PIN2)
        f.visualize(mid, i * 2 + 2, method=fv.VIZ_METHODS[(i + 1) % 6],
                    feature_digest=PIN2, model_digest=PIN2)
    results = []

    def worker():
        results.append(f.model_ids(100))
        results.append(f.stats(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(len(r) == 10 for r in results[::2])
    assert all(r["visualizations"] == 20 for r in results[1::2])
    rec = f.visualization_record("viz-1", 100)
    with pytest.raises(Exception):
        rec.model_id = "m-999"  # frozen
    assert rec.verify()
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=str(MOD.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "feature-viz OK: visualize, verify, compare, pins, audit"
    )
