"""Tests for the human-oversight decision ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "human_oversight.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("human_oversight", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["human_oversight"] = module
    spec.loader.exec_module(module)
    return module


ho = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ho.HUMAN_OVERSIGHT_VERSION == "human-oversight.v1"
    assert ho.SCHEMA_PIN == "northstar.human-oversight.v1"
    assert ho.MODES == (
        "human-in-the-loop",
        "human-on-the-loop",
        "human-in-command",
        "post-hoc-review",
    )
    assert ho.OUTCOMES == (
        "approved",
        "rejected",
        "escalated",
        "amended",
    )
    assert ho.OVERRIDE_DIRECTIONS == (
        "approve",
        "reject",
    )
    assert ho.AUDIT_KINDS == (
        "assigned",
        "reviewed",
        "overridden",
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


# 3. assign roundtrip + verify + frozen-ness
def test_assign_roundtrip():
    h = ho.HumanOversight()
    rec = h.assign("case-1", "human-in-the-loop", 1, PIN, PIN2)
    assert rec.case_id == "case-1"
    assert rec.oversight_mode == "human-in-the-loop"
    assert rec.reviewer_digest == PIN
    assert rec.task_digest == PIN2
    assert rec.verify()
    assert rec.as_dict()["schema"] == ho.SCHEMA_PIN
    with pytest.raises(Exception):
        rec.case_id = "other"  # frozen
    assert h.case_ids(2) == ("case-1",)


# 4. assign bad-input table + duplicate + seq-burn + rejected rows
def test_assign_bad_inputs():
    h = ho.HumanOversight()
    seq = 0
    rejected_before = h.stats(1)["rejected"]
    bad_cases = [
        ("", "human-in-the-loop", PIN, PIN2),  # empty id
        (123, "human-in-the-loop", PIN, PIN2),  # non-str id
        ("x" * 129, "human-in-the-loop", PIN, PIN2),  # too long
        ("c1", "telepathic", PIN, PIN2),  # bad mode
        ("c1", "", PIN, PIN2),
        ("c1", "human-in-the-loop", "not-a-pin", PIN2),  # bad reviewer digest
        ("c1", "human-in-the-loop", PIN, "ab" * 32),  # missing prefix
        ("c1", "human-in-the-loop", PIN, "sha256:" + "zz" * 32),  # bad hex
    ]
    for case_id, mode, rpin, tpin in bad_cases:
        seq += 1
        with pytest.raises(ho.HumanOversightError):
            h.assign(case_id, mode, seq + 1, rpin, tpin)
        seq += 1
    assert h.stats(seq + 1)["rejected"] == rejected_before + len(bad_cases)
    h.assign("dup", "human-on-the-loop", seq + 2, PIN, PIN2)
    with pytest.raises(ho.DuplicateCaseError):
        h.assign("dup", "human-on-the-loop", seq + 3, PIN, PIN2)
    assert h.stats(seq + 4)["rejected"] == rejected_before + len(bad_cases) + 1


# 5. review roundtrip + all outcomes + minted ids
def test_review_all_outcomes():
    h = ho.HumanOversight()
    seq = 1
    for i, outcome in enumerate(ho.OUTCOMES):
        cid = f"case-{i}"
        h.assign(cid, ho.MODES[0], seq, PIN, PIN2)
        seq += 1
        rec = h.review(cid, seq, outcome=outcome, reviewer_digest=PIN)
        seq += 1
        assert rec.review_id == f"rev-{i + 1}"
        assert rec.outcome == outcome
        assert rec.verify()
        assert h.status(cid, seq).has_review is True
        seq += 1


# 6. review refusals: unknown case, duplicate, bad outcome
def test_review_refusals():
    h = ho.HumanOversight()
    with pytest.raises(ho.UnknownCaseError):
        h.review("nope", 1, outcome="approved", reviewer_digest=PIN)
    h.assign("c1", "human-in-the-loop", 2, PIN, PIN2)
    with pytest.raises(ho.BadOutcomeError):
        h.review("c1", 3, outcome="meh", reviewer_digest=PIN)
    h.review("c1", 4, outcome="approved", reviewer_digest=PIN)
    with pytest.raises(ho.AlreadyReviewedError):
        h.review("c1", 5, outcome="approved", reviewer_digest=PIN)
    h.assign("c2", "human-in-the-loop", 6, PIN, PIN2)
    with pytest.raises(ho.BadDigestError):
        h.review("c2", 7, outcome="approved", reviewer_digest="x")
    with pytest.raises(ho.NoReviewError):
        h.review_record("unknown", 8)
    assert h.stats(9)["rejected"] == 4  # unknown, bad outcome, dup, bad digest


# 7. override roundtrip + minted ids + review linkage
def test_override_roundtrip():
    h = ho.HumanOversight()
    h.assign("c1", "human-in-command", 1, PIN, PIN2)
    rev = h.review("c1", 2, outcome="rejected", reviewer_digest=PIN)
    ovr = h.override("c1", 3, direction="approve", reason_digest=PIN3)
    assert ovr.override_id == "ovr-1"
    assert ovr.review_id == rev.review_id
    assert ovr.direction == "approve"
    assert ovr.reason_digest == PIN3
    assert ovr.verify()
    assert h.overridden_ids(4) == ("c1",)
    st = h.status("c1", 5)
    assert st.has_override and st.override_direction == "approve"
    assert st.review_outcome == "rejected"


# 8. override refusals: no review, duplicate, bad direction, unknown case
def test_override_refusals():
    h = ho.HumanOversight()
    h.assign("c1", "human-in-the-loop", 1, PIN, PIN2)
    with pytest.raises(ho.NoReviewError):
        h.override("c1", 2, direction="approve", reason_digest=PIN3)
    with pytest.raises(ho.UnknownCaseError):
        h.override("nope", 3, direction="approve", reason_digest=PIN3)
    h.review("c1", 4, outcome="approved", reviewer_digest=PIN)
    with pytest.raises(ho.BadDirectionError):
        h.override("c1", 5, direction="maybe", reason_digest=PIN3)
    h.override("c1", 6, direction="approve", reason_digest=PIN3)
    with pytest.raises(ho.AlreadyOverriddenError):
        h.override("c1", 7, direction="reject", reason_digest=PIN3)
    with pytest.raises(ho.UnknownCaseError):
        h.override_record("nope", 8)
    assert h.stats(9)["rejected"] == 4


# 9. seq discipline: rewind raises bare, malformed seqs, burn on failure
def test_seq_discipline():
    h = ho.HumanOversight()
    h.assign("c1", "post-hoc-review", 5, PIN, PIN2)
    with pytest.raises(ho.SeqOrderError):
        h.assign("c2", "post-hoc-review", 5, PIN, PIN2)  # rewind: bare
    assert h.stats(6)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(ho.SeqOrderError):
            h.assign("c2", "post-hoc-review", bad, PIN, PIN2)
    h.assign("c2", "post-hoc-review", 7, PIN, PIN2)
    assert h.case_ids(8) == ("c1", "c2")


# 10. view read-purity: same seq twice, no audit rows, no seq consumption
def test_view_read_purity():
    h = ho.HumanOversight()
    h.assign("c1", "human-in-the-loop", 1, PIN, PIN2)
    h.review("c1", 2, outcome="approved", reviewer_digest=PIN)
    n_audit = len(h.audit_log(3))
    st1 = h.status("c1", 3)
    st2 = h.status("c1", 3)
    assert st1.verify() and st2.verify()
    assert len(h.audit_log(3)) == n_audit  # reads add no rows
    assert h.case_ids(3) == ("c1",)
    assert h.reviewed_ids(3) == ("c1",)
    assert h.overridden_ids(3) == ()
    assert h.assignment_record("c1", 3).verify()


# 11. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    h = ho.HumanOversight()
    h.assign("c1", "human-in-the-loop", 1, PIN, PIN2)
    h.review("c1", 2, outcome="approved", reviewer_digest=PIN)
    h.override("c1", 3, direction="reject", reason_digest=PIN3)
    rows = h.audit_log(4)
    assert [r["kind"] for r in rows] == ["assigned", "reviewed", "overridden"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in ho._BANNED_AUDIT_KEYS
    with pytest.raises(ho.AuditKindError):
        ho.human_oversight_audit_event("assigned", 1, reviewer="alice")
    with pytest.raises(ho.AuditKindError):
        ho.human_oversight_audit_event("bogus-kind", 1)
    with pytest.raises(ho.SeqOrderError):
        ho.human_oversight_audit_event("assigned", -1)


# 12. cross-instance digest determinism + tamper breaks verify
def test_determinism_and_tamper():
    def build():
        h = ho.HumanOversight()
        h.assign("c1", "human-on-the-loop", 1, PIN, PIN2)
        h.review("c1", 2, outcome="amended", reviewer_digest=PIN)
        h.override("c1", 3, direction="approve", reason_digest=PIN3)
        return h

    h1, h2 = build(), build()
    assert h1.review_record("c1", 4).digest == h2.review_record("c1", 4).digest
    assert h1.override_record("c1", 4).digest == h2.override_record("c1", 4).digest
    import dataclasses

    rec = h1.review_record("c1", 4)
    tampered = dataclasses.replace(rec, outcome="approved")
    assert tampered.verify() is False
    assert h1.status("c1", 4).integrity_ok is True
    object.__setattr__(rec, "outcome", "approved")
    assert rec.verify() is False
    assert h1.status("c1", 4).integrity_ok is False


# 13. full lifecycle end to end
def test_full_lifecycle():
    h = ho.HumanOversight()
    h.assign("case-x", "human-in-the-loop", 1, PIN, PIN2)
    h.review("case-x", 2, outcome="escalated", reviewer_digest=PIN)
    h.override("case-x", 3, direction="reject", reason_digest=PIN3)
    st = h.status("case-x", 4)
    assert st.case_id == "case-x"
    assert st.oversight_mode == "human-in-the-loop"
    assert st.has_review and st.review_outcome == "escalated"
    assert st.has_override and st.override_direction == "reject"
    assert st.integrity_ok
    stats = h.stats(5)
    assert stats == {"cases": 1, "reviews": 1, "overrides": 1, "rejected": 0}


# 14. concurrency smoke + frozen-ness
def test_concurrency_and_frozen():
    h = ho.HumanOversight()
    for i in range(10):
        cid = f"c{i}"
        h.assign(cid, ho.MODES[i % 4], i * 3 + 1, PIN, PIN2)
        h.review(cid, i * 3 + 2, outcome="approved", reviewer_digest=PIN)
    results = []

    def worker():
        results.append(h.case_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(len(r) == 10 for r in results)
    rec = h.assignment_record("c0", 100)
    with pytest.raises(Exception):
        rec.task_digest = PIN  # frozen
    assert rec.verify()


# 15. main() subprocess check
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=str(MOD.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "human-oversight OK: assign, review, override, status, pins, audit"
    )
