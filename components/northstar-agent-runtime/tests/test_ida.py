"""Tests for ida (Iterative Distillation and Amplification ledger, Simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading

import pytest

from ida import (
    IDA_VERSION,
    SCHEMA_PIN,
    AMP_KINDS,
    DISTILL_STRATEGIES,
    DISTILL_VERDICTS,
    POSTURES,
    AUDIT_KINDS,
    IDAError,
    BadIdError,
    BadDigestError,
    BadKindError,
    BadStrategyError,
    BadVerdictError,
    UnknownAgentError,
    UnknownAmplificationError,
    DuplicateSuccessorError,
    SelfDistillError,
    AlreadyDistilledError,
    SeqOrderError,
    AuditKindError,
    AmplificationRecord,
    DistillationRecord,
    IterationReport,
    IDA,
    ida_audit_event,
)

MOD = None
import ida as _mod

MOD = _mod.__file__

STDLIB_ALLOW = {
    "hashlib",
    "json",
    "threading",
    "dataclasses",
    "typing",
    "__future__",
    "canonical_json",
}


def _digest(tag: bytes = b"content") -> str:
    return "sha256:" + hashlib.sha256(tag).hexdigest()


def _ida() -> IDA:
    return IDA()


# 1. version/schema/vocabulary pins
def test_pins():
    assert IDA_VERSION == "ida.v1"
    assert SCHEMA_PIN == "northstar.ida.v1"
    assert AMP_KINDS == (
        "hch-decomposition",
        "recursive-consultation",
        "parallel-ensemble",
        "deliberative-debate",
        "tree-search-consult",
        "tool-augmented-amp",
        "simulated-oversight",
        "iterative-refinement",
    )
    assert DISTILL_STRATEGIES == (
        "imitation-learning",
        "rl-distillation",
        "model-compression",
        "consultation-distillation",
        "preference-distillation",
        "debate-distillation",
        "oversight-distillation",
        "reward-ensemble",
    )
    assert DISTILL_VERDICTS == (
        "aligned",
        "misaligned",
        "uncertain",
        "not-evaluated",
    )
    assert POSTURES == (
        "unstarted",
        "diverged",
        "uncertain",
        "aligned-chain",
        "unevaluated",
    )
    assert AUDIT_KINDS == ("amplified", "distilled", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(open(_mod.__file__).read())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_ALLOW, imports - STDLIB_ALLOW


# 3. amplify roundtrip + verify + frozen-ness
def test_amplify_roundtrip():
    ida = _ida()
    rec = ida.amplify("m-0", 1, amp_kind="hch-decomposition",
                      agent_digest=_digest())
    assert rec.amplification_id == "amp-1"
    assert rec.agent_id == "m-0"
    assert rec.generation == 0
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        rec.amp_kind = "parallel-ensemble"  # frozen
    assert ida.generation_of("m-0", 2) == 0


# 4. amplify bad-input table + seq-burn + rejected rows
def test_amplify_bad_inputs():
    ida = _ida()
    seq = 0
    bad = [
        (lambda s: ida.amplify("", s), BadIdError),
        (lambda s: ida.amplify(123, s), BadIdError),
        (lambda s: ida.amplify("m-0", s, amp_kind="fax-machine"), BadKindError),
        (lambda s: ida.amplify("m-0", s, agent_digest="raw-bytes"), BadDigestError),
        (lambda s: ida.amplify("m-0", s, agent_digest="md5:abc"), BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert ida.stats(seq + 1)["rejected"] == len(bad)
    # failed mutations consumed their seqs: next mutation must use seq+1
    ida.amplify("m-0", seq + 2)
    assert ida.stats(seq + 3)["amplifications"] == 1


# 5. full amp-kind vocabulary acceptance
def test_all_amp_kinds():
    ida = _ida()
    seq = 0
    for kind in AMP_KINDS:
        seq += 1
        rec = ida.amplify("m-0", seq, amp_kind=kind)
        assert rec.amp_kind == kind
        assert rec.verify()
    assert len(ida.amplifications_for("m-0", seq + 1)) == len(AMP_KINDS)


# 6. distill roundtrip + minted ids + generation math
def test_distill_roundtrip():
    ida = _ida()
    amp = ida.amplify("m-0", 1)
    d = ida.distill(amp.amplification_id, "m-1", 2,
                    strategy="imitation-learning", verdict="aligned",
                    plan_digest=_digest(b"plan"))
    assert d.distillation_id == "dst-1"
    assert d.parent_id == "m-0"
    assert d.successor_id == "m-1"
    assert d.generation == 1
    assert d.verify()
    assert d.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        d.verdict = "misaligned"  # frozen
    assert ida.generation_of("m-1", 3) == 1
    assert ida.distillation_for(amp.amplification_id, 4) == "dst-1"


# 7. distill refusals + seq-burn
def test_distill_refusals():
    ida = _ida()
    amp = ida.amplify("m-0", 1)
    ida.distill(amp.amplification_id, "m-1", 2)
    seq = 2
    # double distillation of the same amplification
    seq += 1
    with pytest.raises(AlreadyDistilledError):
        ida.distill(amp.amplification_id, "m-2", seq)
    # unknown amplification
    seq += 1
    with pytest.raises(UnknownAmplificationError):
        ida.distill("amp-999", "m-9", seq)
    # self distill: successor id equals the parent agent id
    seq += 1
    amp_self = ida.amplify("y-0", seq)
    seq += 1
    with pytest.raises(SelfDistillError):
        ida.distill(amp_self.amplification_id, "y-0", seq)
    # duplicate successor
    seq += 1
    amp2 = ida.amplify("m-0", seq)
    seq += 1
    with pytest.raises(DuplicateSuccessorError):
        ida.distill(amp2.amplification_id, "m-1", seq)
    # bad strategy / verdict
    seq += 1
    amp3 = ida.amplify("m-0", seq)
    seq += 1
    with pytest.raises(BadStrategyError):
        ida.distill(amp3.amplification_id, "m-3", seq, strategy="prayer")
    seq += 1
    with pytest.raises(BadVerdictError):
        ida.distill(amp3.amplification_id, "m-3", seq, verdict="kinda-aligned")
    # rejections accounted (6 refused mutations above)
    assert ida.stats(seq + 1)["rejected"] == 6
    assert ida.stats(seq + 1)["distillations"] == 1


# 8. full strategy x verdict vocabulary acceptance
def test_all_strategies_and_verdicts():
    ida = _ida()
    seq = 0
    n = 0
    for strategy in DISTILL_STRATEGIES:
        for verdict in DISTILL_VERDICTS:
            seq += 1
            amp = ida.amplify(f"m-{n}", seq)
            seq += 1
            d = ida.distill(amp.amplification_id, f"s-{n}", seq,
                            strategy=strategy, verdict=verdict)
            assert d.strategy == strategy and d.verdict == verdict
            assert d.verify()
            n += 1
    assert ida.stats(seq + 1)["distillations"] == n


# 9. iterate posture math (all 5 postures)
def test_iterate_postures():
    ida = _ida()
    # unstarted: empty ledger
    assert ida.iterate(1).posture == "unstarted"
    seq = 1
    # aligned-chain
    seq += 1
    amp = ida.amplify("p", seq)
    seq += 1
    ida.distill(amp.amplification_id, "p-1", seq, verdict="aligned")
    assert ida.iterate(seq + 1, "p").posture == "aligned-chain"
    # diverged
    seq += 2
    amp2 = ida.amplify("q", seq)
    seq += 1
    ida.distill(amp2.amplification_id, "q-1", seq, verdict="misaligned")
    assert ida.iterate(seq + 1, "q").posture == "diverged"
    # uncertain
    seq += 2
    amp3 = ida.amplify("r", seq)
    seq += 1
    ida.distill(amp3.amplification_id, "r-1", seq, verdict="uncertain")
    assert ida.iterate(seq + 1, "r").posture == "uncertain"
    # unevaluated: distillations booked but none evaluated
    seq += 2
    amp4 = ida.amplify("t", seq)
    seq += 1
    ida.distill(amp4.amplification_id, "t-1", seq, verdict="not-evaluated")
    assert ida.iterate(seq + 1, "t").posture == "unevaluated"
    # unevaluated: amplified but never distilled
    seq += 2
    ida.amplify("u", seq)
    assert ida.iterate(seq + 1, "u").posture == "unevaluated"
    with pytest.raises(UnknownAgentError):
        ida.iterate(seq + 2, "ghost")


# 10. iterate generation math + read purity
def test_iterate_generations_and_purity():
    ida = _ida()
    a1 = ida.amplify("m-0", 1)
    ida.distill(a1.amplification_id, "m-1", 2, verdict="aligned")
    a2 = ida.amplify("m-1", 3)
    ida.distill(a2.amplification_id, "m-2", 4, verdict="aligned")
    rep1 = ida.iterate(5, "m-0")
    assert rep1.max_generation == 0
    assert rep1.n_agents == 1
    rep_all = ida.iterate(6)
    assert rep_all.max_generation == 2
    assert rep_all.n_agents == 3
    assert rep_all.verify()
    # read purity: same seq twice, no audit rows, no seq consumption
    n_audit = len(ida.audit_log(7))
    r1 = ida.iterate(7)
    r2 = ida.iterate(7)
    assert r1.verify() and r2.verify()
    assert len(ida.audit_log(7)) == n_audit
    assert r1.max_generation == 2


# 11. seq discipline (rewind bare, malformed seqs, failed-mutation-consumes-seq)
def test_seq_discipline():
    ida = _ida()
    ida.amplify("m-0", 1)
    with pytest.raises(SeqOrderError):
        ida.amplify("m-0", 1)  # rewind: bare
    assert ida.stats(2)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(SeqOrderError):
            ida.amplify("m-1", bad, amp_kind="parallel-ensemble")
    ida.amplify("m-1", 3)
    assert ida.stats(4)["rejected"] == 0
    with pytest.raises(BadKindError):
        ida.amplify("m-2", 5, amp_kind="vibes")
    assert ida.stats(6)["rejected"] == 1  # failed mutation burned seq 5


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ida = _ida()
    amp = ida.amplify("m-0", 1, agent_digest=_digest())
    ida.distill(amp.amplification_id, "m-1", 2, verdict="aligned")
    rows = ida.audit_log(3)
    assert [r["kind"] for r in rows] == ["amplified", "distilled"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in _mod._BANNED_AUDIT_KEYS
    assert ida_audit_event("amplified", 0, agent_id="m-0")["kind"] == "amplified"
    with pytest.raises(AuditKindError):
        ida_audit_event("amplified", 1, weights="raw-tensor")
    with pytest.raises(AuditKindError):
        ida_audit_event("bogus-kind", 1)
    with pytest.raises(SeqOrderError):
        ida_audit_event("amplified", -1)


# 13. cross-instance digest determinism + tamper breaks verify
def test_determinism_and_tamper():
    def build():
        ida = IDA()
        a = ida.amplify("m-0", 1, amp_kind="hch-decomposition")
        ida.distill(a.amplification_id, "m-1", 2, verdict="aligned")
        return ida

    i1, i2 = build(), build()
    assert i1.amplification_record("amp-1", 3).digest == \
        i2.amplification_record("amp-1", 3).digest
    assert i1.distillation_record("dst-1", 3).digest == \
        i2.distillation_record("dst-1", 3).digest
    import dataclasses

    rec = i1.amplification_record("amp-1", 3)
    tampered = dataclasses.replace(rec, amp_kind="parallel-ensemble")
    assert tampered.verify() is False
    object.__setattr__(rec, "amp_kind", "parallel-ensemble")
    assert rec.verify() is False
    rep = i1.iterate(4)
    assert rep.integrity_ok is False


# 14. concurrency smoke + frozen-ness
def test_concurrency_and_frozen():
    ida = _ida()
    for i in range(10):
        ida.amplify(f"m-{i}", i + 1)
    results = []

    def worker():
        results.append(ida.agent_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(len(r) == 10 for r in results)
    rec = ida.amplification_record("amp-1", 100)
    with pytest.raises(Exception):
        rec.agent_id = "x"  # frozen
    assert ida.stats(101) == {
        "agents": 10,
        "amplifications": 10,
        "distillations": 0,
        "rejected": 0,
    }


# 15. main() subprocess check
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, "ida.py"],
        capture_output=True,
        text=True,
        cwd="/home/hatch/workspace/wt/northstar-pushchain/components/northstar-agent-runtime",
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "ida OK: amplify, distill, iterate, pins, audit"
    )
