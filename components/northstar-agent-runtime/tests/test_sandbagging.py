"""Tests for the sandbagging detection ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "sandbagging.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("sandbagging", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["sandbagging"] = module
    spec.loader.exec_module(module)
    return module


sb = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert sb.SANDBAGGING_VERSION == "sandbagging.v1"
    assert sb.SCHEMA_PIN == "northstar.sandbagging.v1"
    assert sb.PROBE_KINDS == (
        "incentive-variation",
        "capability-elicitation",
        "difficulty-sweep",
        "cross-evaluation",
        "refusal-probing",
        "fine-tune-probe",
        "consistency-probe",
        "long-horizon",
    )
    assert sb.DETECT_VERDICTS == (
        "sandbag-detected",
        "no-sandbag",
        "inconclusive",
    )
    assert sb.MEASURES == (
        "adversarial-evaluation",
        "incentive-alignment",
        "capability-restrict",
        "monitoring",
        "retrain",
        "human-review",
        "rollback",
        "shutdown",
    )
    assert sb.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )
    assert set(sb.AUDIT_KINDS) == {
        "tested",
        "detected",
        "mitigated",
        "retired",
        "rejected",
    }


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
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= allowed, f"non-stdlib imports: {imports - allowed}"


# 3. test roundtrip + verify()
def test_test_roundtrip_and_verify():
    g = sb.Sandbagging()
    rec = g.test("sys-a", "incentive-variation", 1, probe_digest=PIN)
    assert rec.test_id == "tst-1"
    assert rec.system_id == "sys-a"
    assert rec.probe_kind == "incentive-variation"
    assert rec.probe_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.sandbagging.v1"
    fetched = g.test_record("tst-1", 2)
    assert fetched == rec
    assert g.system_ids(3) == ("sys-a",)
    assert g.test_ids(4) == ("tst-1",)


# 4. test bad-input table + seq-burn + rejected rows
def test_test_bad_inputs_and_seq_burn():
    g = sb.Sandbagging()
    bad = [
        ("", "incentive-variation", PIN),
        ("x" * 129, "incentive-variation", PIN),
        (None, "incentive-variation", PIN),
        ("ok-1", "not-a-kind", PIN),
        ("ok-1", 123, PIN),
        ("ok-1", "incentive-variation", "raw-not-a-pin"),
        ("ok-1", "incentive-variation", "sha256:" + "zz" * 32),
        ("ok-1", "incentive-variation", "sha256:" + "ab" * 16),
        ("ok-1", "incentive-variation", ""),
    ]
    seq = 0
    for sid, kind, pin in bad:
        seq += 1
        with pytest.raises(sb.SandbaggingError):
            g.test(sid, kind, seq, probe_digest=pin)
    assert g.stats(seq + 1)["rejected"] == len(bad)
    assert len(g.audit_log(seq + 2)) == len(bad)
    assert all(row["kind"] == "rejected" for row in g.audit_log(seq + 3))
    # ledger still usable: seq keeps increasing, system registered by success
    seq += 1
    rec = g.test("ok-1", "capability-elicitation", seq + 1, probe_digest=PIN)
    assert rec.test_id == "tst-1"


# 5. full probe-kind vocabulary acceptance
def test_full_probe_kind_vocabulary():
    g = sb.Sandbagging()
    for i, kind in enumerate(sb.PROBE_KINDS, start=1):
        rec = g.test(f"sys-{i}", kind, i, probe_digest=PIN)
        assert rec.probe_kind == kind
        assert rec.test_id == f"tst-{i}"
        assert rec.verify()
    assert g.stats(len(sb.PROBE_KINDS) + 1)["systems"] == len(sb.PROBE_KINDS)


# 6. detect roundtrip + minted ids
def test_detect_roundtrip_and_minting():
    g = sb.Sandbagging()
    g.test("sys-a", "difficulty-sweep", 1, probe_digest=PIN)
    det = g.detect("tst-1", 2, verdict="sandbag-detected", evidence_digest=PIN2)
    assert det.detection_id == "det-1"
    assert det.test_id == "tst-1"
    assert det.system_id == "sys-a"
    assert det.verdict == "sandbag-detected"
    assert det.evidence_digest == PIN2
    assert det.verify()
    assert det.as_dict()["schema"] == "northstar.sandbagging.v1"
    assert g.detection_ids(3) == ("det-1",)
    assert g.detections_for("tst-1", 4) == ("det-1",)


# 7. detect bad-input table + seq-burn
def test_detect_bad_inputs_and_seq_burn():
    g = sb.Sandbagging()
    g.test("sys-a", "cross-evaluation", 1, probe_digest=PIN)
    bad = [
        ("", "sandbag-detected", PIN),
        (123, "sandbag-detected", PIN),
        ("ghost", "sandbag-detected", PIN),
        ("tst-1", "not-a-verdict", PIN),
        ("tst-1", 123, PIN),
        ("tst-1", "sandbag-detected", "raw"),
        ("tst-1", "sandbag-detected", "sha256:" + "zz" * 32),
        ("tst-1", "sandbag-detected", ""),
    ]
    seq = 1
    for tid, verdict, pin in bad:
        seq += 1
        with pytest.raises(sb.SandbaggingError):
            g.detect(tid, seq, verdict=verdict, evidence_digest=pin)
    assert g.stats(seq + 1)["rejected"] == len(bad)
    det = g.detect("tst-1", seq + 1, verdict="no-sandbag", evidence_digest=PIN2)
    assert det.detection_id == "det-1"


# 8. full verdict vocabulary acceptance
def test_full_verdict_vocabulary():
    g = sb.Sandbagging()
    g.test("sys-a", "refusal-probing", 1, probe_digest=PIN)
    for i, verdict in enumerate(sb.DETECT_VERDICTS, start=2):
        det = g.detect("tst-1", i, verdict=verdict, evidence_digest=PIN2)
        assert det.verdict == verdict
        assert det.verify()


# 9. mitigate roundtrip + all-measure acceptance
def test_mitigate_roundtrip_and_measures():
    g = sb.Sandbagging()
    g.test("sys-a", "fine-tune-probe", 1, probe_digest=PIN)
    g.detect("tst-1", 2, verdict="sandbag-detected", evidence_digest=PIN2)
    seq = 2
    for measure in sb.MEASURES:
        # fresh detection per measure (one mitigation per detection)
        g.test("sys-a", "consistency-probe", seq + 1, probe_digest=PIN)
        seq += 1
        det = g.detect(
            g.test_ids(seq)[-1], seq + 1, verdict="sandbag-detected",
            evidence_digest=PIN2,
        )
        seq += 1
        mit = g.mitigate(det.detection_id, seq + 1, measure=measure, plan_digest=PIN3)
        seq += 1
        assert mit.measure == measure
        assert mit.verify()
        assert mit.as_dict()["schema"] == "northstar.sandbagging.v1"


# 10. mitigate refusals: not-needed, double, unknown
def test_mitigate_refusals():
    g = sb.Sandbagging()
    g.test("sys-a", "long-horizon", 1, probe_digest=PIN)
    clean = g.detect("tst-1", 2, verdict="no-sandbag", evidence_digest=PIN2)
    inconclusive = g.detect("tst-1", 3, verdict="inconclusive", evidence_digest=PIN2)
    with pytest.raises(sb.MitigationNotNeededError):
        g.mitigate(clean.detection_id, 4, measure="monitoring", plan_digest=PIN3)
    with pytest.raises(sb.MitigationNotNeededError):
        g.mitigate(inconclusive.detection_id, 5, measure="monitoring", plan_digest=PIN3)
    with pytest.raises(sb.UnknownDetectionError):
        g.mitigate("det-ghost", 6, measure="monitoring", plan_digest=PIN3)
    det = g.detect("tst-1", 7, verdict="sandbag-detected", evidence_digest=PIN2)
    mit = g.mitigate(det.detection_id, 8, measure="monitoring", plan_digest=PIN3)
    assert mit.mitigation_id == "mit-1"
    with pytest.raises(sb.AlreadyMitigatedError):
        g.mitigate(det.detection_id, 9, measure="shutdown", plan_digest=PIN3)
    # bad measure on a fresh detection: ordering hits BadMeasureError
    det2 = g.detect("tst-1", 10, verdict="sandbag-detected", evidence_digest=PIN2)
    with pytest.raises(sb.BadMeasureError):
        g.mitigate(det2.detection_id, 11, measure="not-a-measure", plan_digest=PIN3)
    assert g.stats(12)["rejected"] == 5


# 11. retire terminality + id non-recycling + post-retire refusals
def test_retire_terminality():
    g = sb.Sandbagging()
    g.test("sys-a", "incentive-variation", 1, probe_digest=PIN)
    rec = g.retire("sys-a", 2, reason="decommissioned")
    assert rec.system_id == "sys-a"
    assert rec.reason == "decommissioned"
    assert rec.verify()
    assert g.retired_ids(3) == ("sys-a",)
    # ids never recycled
    with pytest.raises(sb.RetiredSystemError):
        g.test("sys-a", "incentive-variation", 4, probe_digest=PIN)
    with pytest.raises(sb.RetiredSystemError):
        g.retire("sys-a", 5, reason="manual")
    # unknown system
    with pytest.raises(sb.UnknownSystemError):
        g.retire("sys-ghost", 6, reason="manual")
    # bad reason on a known live system
    g.test("sys-b", "incentive-variation", 7, probe_digest=PIN)
    with pytest.raises(sb.BadReasonError):
        g.retire("sys-b", 8, reason="not-a-reason")
    # reads still work after retirement
    assert g.report("sys-a", 9).verify()
    assert g.system_ids(10) == ("sys-a", "sys-b")


# 12. seq discipline: rewind bare, malformed, failed-mutation-consumes-seq
def test_seq_discipline():
    g = sb.Sandbagging()
    g.test("sys-a", "incentive-variation", 5, probe_digest=PIN)
    # rewind raises bare without booking a rejected row
    with pytest.raises(sb.SeqOrderError):
        g.test("sys-b", "incentive-variation", 5, probe_digest=PIN)
    assert g.stats(6)["rejected"] == 0
    # malformed seqs on reads raise without consumption
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(sb.SeqOrderError):
            g.system_ids(bad)
    # failed mutation consumes its seq: the next valid call continues
    with pytest.raises(sb.BadProbeKindError):
        g.test("sys-b", "nope", 6, probe_digest=PIN)
    rec = g.test("sys-b", "capability-elicitation", 7, probe_digest=PIN)
    assert rec.test_id == "tst-2"
    assert g.stats(8)["rejected"] == 1


# 13. report math + read purity + tamper-as-data + unknown refusal
def test_report_math_purity_tamper():
    g = sb.Sandbagging()
    g.test("sys-a", "incentive-variation", 1, probe_digest=PIN)
    g.detect("tst-1", 2, verdict="sandbag-detected", evidence_digest=PIN2)
    g.mitigate("det-1", 3, measure="monitoring", plan_digest=PIN3)
    g.test("sys-a", "difficulty-sweep", 4, probe_digest=PIN)
    g.detect("tst-2", 5, verdict="no-sandbag", evidence_digest=PIN2)
    rep = g.report("sys-a", 6)
    assert rep.n_tests == 2
    assert rep.n_detections == 2
    assert rep.n_sandbag_detected == 1
    assert rep.n_mitigations == 1
    assert rep.integrity_ok is True
    assert rep.verify()
    # same-seq reads twice: pure, no audit rows, no consumption
    before = len(g.audit_log(7))
    assert g.report("sys-a", 8) == g.report("sys-a", 8)
    assert len(g.audit_log(8)) == before
    # tamper breaks verify() on the record; integrity_ok flips as data
    rec = g.test_record("tst-1", 9)
    object.__setattr__(rec, "probe_kind", "minted-money")
    assert not rec.verify()
    rep2 = g.report("sys-a", 10)
    assert rep2.integrity_ok is False
    assert rep2.verify()  # tamper reported, never raised
    # unknown system is refused
    with pytest.raises(sb.UnknownSystemError):
        g.report("sys-ghost", 11)


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    g = sb.Sandbagging()
    g.test("sys-a", "incentive-variation", 1, probe_digest=PIN)
    g.detect("tst-1", 2, verdict="sandbag-detected", evidence_digest=PIN2)
    g.mitigate("det-1", 3, measure="adversarial-evaluation", plan_digest=PIN3)
    rows = g.audit_log(4)
    assert [r["kind"] for r in rows] == ["tested", "detected", "mitigated"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in sb._BANNED_AUDIT_KEYS
    with pytest.raises(sb.AuditKindError):
        sb.sandbagging_audit_event("bogus-kind", 1)
    with pytest.raises(sb.AuditKindError):
        sb.sandbagging_audit_event("tested", 1, transcript="raw-text")
    with pytest.raises(sb.SeqOrderError):
        sb.sandbagging_audit_event("tested", -1)


# 15. cross-instance determinism + frozen-ness + thread smoke + main()
def test_determinism_frozen_and_threads():
    g1 = sb.Sandbagging()
    g2 = sb.Sandbagging()
    for i, g in enumerate((g1, g2), start=1):
        g.test("sys-a", "incentive-variation", i, probe_digest=PIN)
    assert g1.test_record("tst-1", 3).digest == g2.test_record("tst-1", 3).digest
    # records are frozen
    rec = g1.test_record("tst-1", 4)
    with pytest.raises(Exception):
        rec.probe_kind = "x"  # type: ignore
    # 8 threads of pure reads with the same seq
    errors = []

    def reader():
        try:
            for _ in range(50):
                g1.report("sys-a", 5)
                g1.test_record("tst-1", 5)
                g1.stats(5)
                g1.audit_log(5)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # main() subprocess check
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    assert "sandbagging OK: test, detect, mitigate, retire, pins, audit" in proc.stdout
