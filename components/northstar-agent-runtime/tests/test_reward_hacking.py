"""Tests for the reward-hacking detection ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "reward_hacking.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("reward_hacking", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["reward_hacking"] = module
    spec.loader.exec_module(module)
    return module


rh = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert rh.REWARD_HACKING_VERSION == "reward-hacking.v1"
    assert rh.SCHEMA_PIN == "northstar.reward-hacking.v1"
    assert rh.PROBE_KINDS == (
        "specification-gaming",
        "reward-tampering",
        "proxy-optimization",
        "goal-misgeneralization",
        "deceptive-evaluation",
        "sandbagging",
        "gradient-hacking",
        "feedback-tampering",
    )
    assert rh.DETECT_VERDICTS == (
        "hack-detected",
        "no-hack",
        "inconclusive",
    )
    assert rh.MEASURES == (
        "respecify-reward",
        "constrain-optimizer",
        "adversarial-evaluation",
        "shutdown",
        "rollback",
        "human-review",
        "monitor",
        "retrain-from-checkpoint",
    )
    assert rh.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )
    assert set(rh.AUDIT_KINDS) == {
        "probed",
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
def test_probe_roundtrip_and_verify():
    g = rh.RewardHacking()
    rec = g.test("sys-a", "specification-gaming", 1, probe_digest=PIN)
    assert rec.probe_id == "prb-1"
    assert rec.system_id == "sys-a"
    assert rec.probe_kind == "specification-gaming"
    assert rec.probe_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.reward-hacking.v1"
    fetched = g.probe_record("prb-1", 2)
    assert fetched == rec
    assert g.system_ids(3) == ("sys-a",)
    assert g.probe_ids(4) == ("prb-1",)


# 4. test bad-input table + seq-burn + rejected rows
def test_probe_bad_inputs_and_seq_burn():
    g = rh.RewardHacking()
    bad = [
        ("", "specification-gaming", PIN),
        ("x" * 129, "specification-gaming", PIN),
        (None, "specification-gaming", PIN),
        ("ok-1", "not-a-kind", PIN),
        ("ok-1", 123, PIN),
        ("ok-1", "specification-gaming", "raw-not-a-pin"),
        ("ok-1", "specification-gaming", "sha256:" + "zz" * 32),
        ("ok-1", "specification-gaming", "sha256:" + "ab" * 16),
        ("ok-1", "specification-gaming", ""),
    ]
    seq = 0
    for sid, kind, pin in bad:
        seq += 1
        with pytest.raises(rh.RewardHackingError):
            g.test(sid, kind, seq, probe_digest=pin)
    assert g.stats(seq + 1)["rejected"] == len(bad)
    assert len(g.audit_log(seq + 2)) == len(bad)
    assert all(row["kind"] == "rejected" for row in g.audit_log(seq + 3))
    # ledger still usable: seq keeps increasing, system registered by success
    seq += 1
    rec = g.test("ok-1", "reward-tampering", seq + 1, probe_digest=PIN)
    assert rec.probe_id == "prb-1"


# 5. full probe-kind vocabulary acceptance
def test_all_probe_kinds_accepted():
    g = rh.RewardHacking()
    for i, kind in enumerate(rh.PROBE_KINDS, start=1):
        rec = g.test(f"sys-{kind}", kind, i, probe_digest=PIN)
        assert rec.probe_id == f"prb-{i}"
        assert rec.verify()


# 6. detect roundtrip + minted ids + verdict vocabulary
def test_detect_roundtrip_and_minting():
    g = rh.RewardHacking()
    g.test("sys-a", "specification-gaming", 1, probe_digest=PIN)
    g.test("sys-b", "reward-tampering", 2, probe_digest=PIN)
    g.test("sys-c", "sandbagging", 3, probe_digest=PIN)
    seq = 3
    for verdict in rh.DETECT_VERDICTS:
        seq += 1
        det = g.detect("prb-1", seq, verdict=verdict, evidence_digest=PIN2)
        assert det.detection_id == f"det-{det.detection_id.split('-')[1]}"
        assert det.verify()
        assert det.probe_id == "prb-1"
        assert det.system_id == "sys-a"
    assert g.detections_for("prb-1", seq + 1) == ("det-1", "det-2", "det-3")
    assert g.detection_ids(seq + 2) == ("det-1", "det-2", "det-3")


# 7. detect bad-input table + unknown probe refusal + seq-burn
def test_detect_bad_inputs_and_unknown_probe():
    g = rh.RewardHacking()
    g.test("sys-a", "specification-gaming", 1, probe_digest=PIN)
    bad = [
        ("", "inconclusive", PIN),
        ("prb-999", "inconclusive", PIN),
        ("prb-1", "not-a-verdict", PIN),
        ("prb-1", 42, PIN),
        ("prb-1", "inconclusive", "raw"),
        ("prb-1", "inconclusive", "sha256:" + "zz" * 32),
        ("prb-1", "inconclusive", ""),
        (None, "inconclusive", PIN),
    ]
    seq = 1
    for pid, verdict, pin in bad:
        seq += 1
        with pytest.raises(rh.RewardHackingError):
            g.detect(pid, seq, verdict=verdict, evidence_digest=pin)
    assert g.stats(seq + 1)["rejected"] == len(bad)


# 8. mitigate roundtrip + minted ids + all-measures vocabulary
def test_mitigate_roundtrip_and_all_measures():
    g = rh.RewardHacking()
    seq = 0
    mids = []
    for i, measure in enumerate(rh.MEASURES, start=1):
        seq += 1
        g.test(f"sys-{measure}", "specification-gaming", seq, probe_digest=PIN)
        seq += 1
        det = g.detect(f"prb-{i}", seq, verdict="hack-detected",
                       evidence_digest=PIN2)
        seq += 1
        mit = g.mitigate(det.detection_id, seq, measure=measure,
                         plan_digest=PIN3)
        assert mit.mitigation_id == f"mit-{i}"
        assert mit.verify()
        mids.append(mit.mitigation_id)
    assert g.mitigation_ids(seq + 1) == tuple(mids)
    assert g.mitigations_for("sys-respecify-reward", seq + 2) == ("mit-1",)


# 9. mitigate gating: not-needed / already / unknown
def test_mitigate_gating():
    g = rh.RewardHacking()
    g.test("sys-a", "specification-gaming", 1, probe_digest=PIN)
    g.test("sys-b", "sandbagging", 2, probe_digest=PIN)
    g.test("sys-c", "feedback-tampering", 3, probe_digest=PIN)
    det_no = g.detect("prb-1", 4, verdict="no-hack", evidence_digest=PIN2)
    det_inc = g.detect("prb-2", 5, verdict="inconclusive", evidence_digest=PIN2)
    det_yes = g.detect("prb-3", 6, verdict="hack-detected", evidence_digest=PIN2)
    # no-hack verdict needs no mitigation
    with pytest.raises(rh.MitigationNotNeededError):
        g.mitigate(det_no.detection_id, 7, measure="shutdown", plan_digest=PIN3)
    # inconclusive verdict needs no mitigation
    with pytest.raises(rh.MitigationNotNeededError):
        g.mitigate(det_inc.detection_id, 8, measure="monitor", plan_digest=PIN3)
    # unknown detection
    with pytest.raises(rh.UnknownDetectionError):
        g.mitigate("det-999", 9, measure="monitor", plan_digest=PIN3)
    # bad measure burns a seq on the *live* detection
    with pytest.raises(rh.BadMeasureError):
        g.mitigate(det_yes.detection_id, 10, measure="vibes", plan_digest=PIN3)
    # real mitigation, then double-mitigation refused
    mit = g.mitigate(det_yes.detection_id, 11, measure="rollback",
                     plan_digest=PIN3)
    assert mit.mitigation_id == "mit-1"
    with pytest.raises(rh.AlreadyMitigatedError):
        g.mitigate(det_yes.detection_id, 12, measure="monitor", plan_digest=PIN3)
    assert g.stats(13)["rejected"] == 5
    fetched = g.mitigation_record("mit-1", 14)
    assert fetched == mit
    assert fetched.measure == "rollback"


# 10. retire terminality + id non-recycling + post-retire refusals
def test_retire_terminality():
    g = rh.RewardHacking()
    g.test("sys-a", "specification-gaming", 1, probe_digest=PIN)
    g.test("sys-b", "sandbagging", 2, probe_digest=PIN)
    det = g.detect("prb-1", 3, verdict="hack-detected", evidence_digest=PIN2)
    # bad reason on a known live system burns a seq
    with pytest.raises(rh.BadReasonError):
        g.retire("sys-b", 4, reason="vibes")
    rec = g.retire("sys-a", 5, reason="decommissioned")
    assert rec.verify()
    assert g.retired_ids(6) == ("sys-a",)
    # post-retire mutations all refused, fail-closed
    with pytest.raises(rh.RetiredSystemError):
        g.test("sys-a", "sandbagging", 7, probe_digest=PIN)
    with pytest.raises(rh.RetiredSystemError):
        g.detect("prb-1", 8, verdict="hack-detected", evidence_digest=PIN2)
    with pytest.raises(rh.RetiredSystemError):
        g.mitigate(det.detection_id, 9, measure="shutdown", plan_digest=PIN3)
    with pytest.raises(rh.RetiredSystemError):
        g.retire("sys-a", 10, reason="manual")
    # reads still work after retire
    assert g.probe_record("prb-1", 11).system_id == "sys-a"
    rep = g.report("sys-a", 12)
    assert rep.n_probes == 1
    assert g.stats(13)["rejected"] == 5


# 11. seq discipline: rewind bare, malformed seqs, failed-mutation burns
def test_seq_discipline():
    g = rh.RewardHacking()
    g.test("sys-a", "specification-gaming", 1, probe_digest=PIN)
    # rewind raises bare without consuming / without a rejected row
    with pytest.raises(rh.SeqOrderError):
        g.test("sys-b", "sandbagging", 1, probe_digest=PIN)
    with pytest.raises(rh.SeqOrderError):
        g.detect("prb-1", 1, verdict="no-hack", evidence_digest=PIN2)
    assert g.stats(2)["rejected"] == 0
    # malformed seqs on reads and mutations
    for bad in (True, "1", 1.5, None, 0, -3):
        with pytest.raises(rh.SeqOrderError):
            g.system_ids(bad)
        with pytest.raises(rh.SeqOrderError):
            g.test("sys-b", "sandbagging", bad, probe_digest=PIN)
    # failed mutation consumes its seq
    with pytest.raises(rh.BadProbeKindError):
        g.test("sys-b", "vibes", 2, probe_digest=PIN)
    assert g.stats(3)["rejected"] == 1
    # ledger continues at strictly increasing seqs only
    rec = g.test("sys-b", "sandbagging", 3, probe_digest=PIN)
    assert rec.probe_id == "prb-2"


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    g = rh.RewardHacking()
    g.test("sys-a", "specification-gaming", 1, probe_digest=PIN)
    g.detect("prb-1", 2, verdict="hack-detected", evidence_digest=PIN2)
    g.mitigate("det-1", 3, measure="human-review", plan_digest=PIN3)
    g.retire("sys-a", 4, reason="manual")
    log = g.audit_log(5)
    kinds = [row["kind"] for row in log]
    assert kinds == ["probed", "detected", "mitigated", "retired"]
    for row in log:
        assert row["schema"] == "audit.ndjson/1"
        assert row["seq"] >= 1
    # pinned vocabulary values remain emittable as declared data
    det_row = log[1]
    assert det_row["details"]["verdict"] == "hack-detected"
    # raw material keys are banned at the builder level
    for banned in ("reward", "policy", "trajectory", "gradient", "evidence",
                   "report", "content", "prompt"):
        with pytest.raises(rh.AuditKindError):
            rh.reward_hacking_audit_event("probed", 9, **{banned: "x"})
    # bad kind
    with pytest.raises(rh.AuditKindError):
        rh.reward_hacking_audit_event("hacked", 9)
    # builder seq must be non-negative int
    with pytest.raises(rh.SeqOrderError):
        rh.reward_hacking_audit_event("probed", -1)
    # one failure booked a rejected row
    with pytest.raises(rh.BadProbeKindError):
        g.test("sys-b", "vibes", 6, probe_digest=PIN)
    log2 = g.audit_log(7)
    assert log2[-1]["kind"] == "rejected"
    assert log2[-1]["details"]["method"] == "test"
    assert log2[-1]["details"]["error"] == "BadProbeKindError"


# 13. report read purity + tallies + integrity flip on tamper
def test_report_read_purity_and_integrity():
    g = rh.RewardHacking()
    g.test("sys-a", "specification-gaming", 1, probe_digest=PIN)
    g.test("sys-a", "reward-tampering", 2, probe_digest=PIN)
    g.detect("prb-1", 3, verdict="hack-detected", evidence_digest=PIN2)
    g.detect("prb-2", 4, verdict="no-hack", evidence_digest=PIN2)
    g.mitigate("det-1", 5, measure="respecify-reward", plan_digest=PIN3)
    rep = g.report("sys-a", 6)
    assert rep.n_probes == 2
    assert rep.n_detections == 2
    assert rep.n_hack_detected == 1
    assert rep.n_mitigations == 1
    assert rep.integrity_ok is True
    assert rep.verify()
    # same-seq reads twice: pure, no audit rows, no consumption
    before = len(g.audit_log(7))
    assert g.report("sys-a", 8) == g.report("sys-a", 8)
    assert len(g.audit_log(8)) == before
    # tamper breaks verify() on the record; integrity_ok flips as data
    rec = g.probe_record("prb-1", 9)
    object.__setattr__(rec, "probe_kind", "minted-money")
    assert not rec.verify()
    rep2 = g.report("sys-a", 10)
    assert rep2.integrity_ok is False
    assert rep2.verify()  # tamper reported, never raised
    # unknown system is refused
    with pytest.raises(rh.UnknownSystemError):
        g.report("sys-ghost", 11)


# 14. cross-instance determinism + frozen-ness + read thread smoke
def test_determinism_frozen_and_threads():
    g1 = rh.RewardHacking()
    g2 = rh.RewardHacking()
    for i, g in enumerate((g1, g2), start=1):
        g.test("sys-a", "specification-gaming", i, probe_digest=PIN)
    assert g1.probe_record("prb-1", 3).digest == g2.probe_record("prb-1", 3).digest
    # records are frozen
    rec = g1.probe_record("prb-1", 4)
    with pytest.raises(Exception):
        rec.probe_kind = "x"  # type: ignore
    # 8 threads of pure reads with the same seq
    errors = []

    def reader():
        try:
            for _ in range(50):
                g1.report("sys-a", 5)
                g1.probe_record("prb-1", 5)
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


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    assert "reward-hacking OK: test, detect, mitigate, retire, pins, audit" in proc.stdout
