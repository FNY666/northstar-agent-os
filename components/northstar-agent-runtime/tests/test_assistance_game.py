"""Tests for assistance_game (assistance-game session decision ledger, simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import assistance_game as ag_mod
from assistance_game import (
    ASSISTANCE_GAME_VERSION,
    SCHEMA_PIN,
    EPISODE_KINDS,
    PLAY_OUTCOMES,
    EVAL_METRICS,
    RETIRE_REASONS,
    POSTURES,
    AUDIT_KINDS,
    AssistanceGameError,
    BadIdError,
    BadDigestError,
    BadKindError,
    BadOutcomeError,
    BadMetricError,
    BadValueError,
    BadReasonError,
    UnknownSessionError,
    UnknownPlayError,
    UnknownEvaluationError,
    RetiredSessionError,
    SeqOrderError,
    AuditKindError,
    PlayRecord,
    EvaluationRecord,
    RetireRecord,
    SessionStatus,
    VerificationReport,
    AssistanceGame,
    assistance_game_audit_event,
)

MOD = Path(ag_mod.__file__)

STDLIB_ALLOW = {
    "hashlib",
    "threading",
    "dataclasses",
    "typing",
    "__future__",
    "canonical_json",
    "ast",
    "inspect",
    "json",
}


def _digest(tag: bytes = b"content") -> str:
    return "sha256:" + hashlib.sha256(tag).hexdigest()


def _led() -> AssistanceGame:
    return AssistanceGame()


# 1. version/schema pins + vocabulary pins
def test_pins():
    assert ASSISTANCE_GAME_VERSION == "assistance-game.v1"
    assert SCHEMA_PIN == "northstar.assistance-game.v1"
    assert EPISODE_KINDS == (
        "value-elicitation",
        "preference-probing",
        "task-completion",
        "corrigible-oversight",
        "demonstration",
        "correction-loop",
        "delegation-check",
        "uncertainty-clarification",
    )
    assert PLAY_OUTCOMES == ("improved", "degraded", "inconclusive", "not-run")
    assert EVAL_METRICS == (
        "regret",
        "reward-gap",
        "preference-alignment",
        "safety-violation",
        "human-satisfaction",
        "autonomy-preserved",
    )
    assert RETIRE_REASONS == (
        "manual",
        "superseded",
        "task-complete",
        "policy-revoked",
    )
    assert POSTURES == (
        "unplayed",
        "improved",
        "contested",
        "degraded",
        "unevaluated",
    )
    assert AUDIT_KINDS == ("played", "evaluated", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_ALLOW, imports - STDLIB_ALLOW
    assert AssistanceGame.stdlib_only()


# 3. play roundtrip + verify + frozen-ness + minted ids
def test_play_roundtrip():
    g = _led()
    rec = g.play("s-1", 1, episode_kind="value-elicitation",
                 outcome="improved", session_digest=_digest())
    assert isinstance(rec, PlayRecord)
    assert rec.play_id == "ply-1"
    assert rec.session_id == "s-1"
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        rec.outcome = "degraded"  # frozen
    rec2 = g.play("s-1", 2, outcome="inconclusive")
    assert rec2.play_id == "ply-2"
    assert g.plays_for("s-1", 3) == ("ply-1", "ply-2")


# 4. play bad-input table + seq-burn + rejected-row accounting + rewind bare
def test_play_bad_inputs():
    g = _led()
    seq = 0
    bad = [
        (lambda s: g.play("", s), BadIdError),
        (lambda s: g.play(123, s), BadIdError),
        (lambda s: g.play("x" * 129, s), BadIdError),
        (lambda s: g.play("s-1", s, episode_kind="vibes"), BadKindError),
        (lambda s: g.play("s-1", s, outcome="perfection"), BadOutcomeError),
        (lambda s: g.play("s-1", s, session_digest="raw-bytes"),
         BadDigestError),
        (lambda s: g.play("s-1", s, session_digest="md5:abc"),
         BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert len(g.audit_log(seq + 1)) == len(bad)  # all burned as rejected
    assert g.stats(seq + 1)["rejected"] == len(bad)
    # rewind raises bare with no new rejected row
    g.play("s-ok", seq + 1)
    with pytest.raises(SeqOrderError):
        g.play("s-2", seq + 1)  # rewind: bare
    assert g.stats(seq + 2)["rejected"] == len(bad)


# 5. full episode-kind vocabulary acceptance
def test_episode_kind_vocabulary():
    g = _led()
    seq = 0
    for kind in EPISODE_KINDS:
        seq += 1
        rec = g.play("s-kinds", seq, episode_kind=kind, outcome="improved")
        assert rec.episode_kind == kind
        assert rec.verify()
    assert g.stats(seq + 1)["plays"] == len(EPISODE_KINDS)


# 6. evaluate roundtrip + minted ids + verify
def test_evaluate_roundtrip():
    g = _led()
    g.play("s-1", 1)
    ev = g.evaluate("s-1", 2, metric="preference-alignment", value=88,
                    eval_digest=_digest(b"eval"))
    assert isinstance(ev, EvaluationRecord)
    assert ev.evaluation_id == "evl-1"
    assert ev.metric == "preference-alignment"
    assert ev.value == 88
    assert ev.verify()
    assert ev.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        ev.value = 0  # frozen
    ev2 = g.evaluate("s-1", 3, metric="regret", value=5)
    assert ev2.evaluation_id == "evl-2"
    assert g.evaluations_for("s-1", 4) == ("evl-1", "evl-2")


# 7. evaluate refusals: unknown / retired / bad metric / bad digest
def test_evaluate_refusals():
    g = _led()
    with pytest.raises(UnknownSessionError):
        g.evaluate("ghost", 1)
    g.play("s-1", 2)
    g.retire("s-1", 3)
    with pytest.raises(RetiredSessionError):
        g.evaluate("s-1", 4)
    with pytest.raises(BadMetricError):
        g.evaluate("s-1", 5, metric="vibes")
    with pytest.raises(BadDigestError):
        g.evaluate("s-1", 6, metric="regret", value=50,
                   eval_digest="not-a-pin")
    with pytest.raises(RetiredSessionError):
        g.play("s-1", 7)
    assert g.stats(8)["rejected"] == 5


# 8. value boundaries: 0/100 accepted; bool/negative/over/float refused
def test_value_boundaries():
    g = _led()
    g.play("s", 1)
    assert g.evaluate("s", 2, value=0).value == 0
    assert g.evaluate("s", 3, value=100).value == 100
    seq = 3
    for bad in (True, False, -1, 101, 1.5, "50", None):
        seq += 1
        with pytest.raises(BadValueError):
            g.evaluate("s", seq, value=bad)
    assert g.stats(seq + 1)["rejected"] == 7


# 9. verify posture math + unknown refusal
def test_verify_posture_math():
    g = _led()
    g.play("s-1", 1, outcome="improved")
    assert g.verify("s-1", 2).posture == "unevaluated"
    g.evaluate("s-1", 3, metric="regret", value=10)
    assert g.verify("s-1", 4).posture == "improved"
    g.play("s-2", 5, outcome="inconclusive")
    assert g.verify("s-2", 6).posture == "contested"
    g.play("s-3", 7, outcome="degraded")
    assert g.verify("s-3", 8).posture == "degraded"
    # degraded outranks everything, even with evaluations booked
    g.evaluate("s-3", 9, metric="human-satisfaction", value=99)
    assert g.verify("s-3", 10).posture == "degraded"
    with pytest.raises(UnknownSessionError):
        g.verify("ghost", 11)


# 10. verify/status read purity: same-seq twice, no audit rows, no consume
def test_read_purity():
    g = _led()
    g.play("s-1", 1, outcome="improved")
    g.evaluate("s-1", 2, metric="autonomy-preserved", value=70)
    n_audit = len(g.audit_log(3))
    v1 = g.verify("s-1", 3)
    v2 = g.verify("s-1", 3)
    assert v1.verify() and v2.verify()
    assert v1.posture == v2.posture == "improved"
    st1 = g.status("s-1", 3)
    st2 = g.status("s-1", 3)
    assert st1.verify() and st2.verify()
    assert st1.integrity_ok and st2.integrity_ok
    assert len(g.audit_log(3)) == n_audit  # reads add no rows
    assert g.session_ids(3) == ("s-1",)
    assert g.retired_ids(3) == ()


# 11. retire terminality + id non-recycling + post-retire reads
def test_retire_terminality():
    g = _led()
    g.play("s-1", 1)
    g.evaluate("s-1", 2, value=42)
    with pytest.raises(BadReasonError):
        g.retire("s-1", 3, reason="vibes")
    r = g.retire("s-1", 4, reason="task-complete")
    assert isinstance(r, RetireRecord)
    assert r.verify()
    with pytest.raises(RetiredSessionError):
        g.retire("s-1", 5)  # double retire refused
    assert g.retired_ids(6) == ("s-1",)
    # reads still work after retirement
    assert g.status("s-1", 6).retired is True
    assert g.verify("s-1", 6).posture == "improved"
    # retired ids are never recycled
    with pytest.raises(RetiredSessionError):
        g.play("s-1", 7)
    assert g.stats(8)["rejected"] == 3


# 12. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes
def test_seq_discipline():
    g = _led()
    g.play("s-1", 5, episode_kind="demonstration")
    with pytest.raises(SeqOrderError):
        g.play("s-2", 5)  # rewind: bare
    assert g.stats(6)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(SeqOrderError):
            g.play("s-2", bad)
    g.play("s-2", 7)  # fresh seq proceeds
    assert g.session_ids(8) == ("s-1", "s-2")


# 13. audit shapes + leak ban + bad-kind + bad audit seq
def test_audit_shapes_and_leak_ban():
    g = _led()
    g.play("s-1", 1, episode_kind="demonstration", outcome="improved")
    g.evaluate("s-1", 2, metric="regret", value=10)
    g.retire("s-1", 3)
    rows = g.audit_log(4)
    assert [r["kind"] for r in rows] == [
        "assistance-game.played",
        "assistance-game.evaluated",
        "assistance-game.retired",
    ]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
    with pytest.raises(AuditKindError):
        assistance_game_audit_event("played", 1, theta="x")
    with pytest.raises(AuditKindError):
        assistance_game_audit_event("bogus-kind", 1)
    with pytest.raises(SeqOrderError):
        assistance_game_audit_event("played", -1)


# 14. cross-instance digest determinism + tamper breaks verify + integrity_ok
def test_determinism_and_tamper():
    def build():
        g = _led()
        g.play("s-1", 1, episode_kind="value-elicitation",
               outcome="improved", session_digest=_digest(b"d"))
        g.evaluate("s-1", 2, metric="regret", value=10,
                   eval_digest=_digest(b"e"))
        return g

    g1, g2 = build(), build()
    assert g1.play_record("ply-1", 3).digest == g2.play_record("ply-1", 3).digest
    assert (
        g1.evaluation_record("evl-1", 3).digest
        == g2.evaluation_record("evl-1", 3).digest
    )
    assert g1.verify("s-1", 3).digest == g2.verify("s-1", 3).digest
    rec = g1.play_record("ply-1", 3)
    object.__setattr__(rec, "outcome", "degraded")
    assert rec.verify() is False
    assert g1.verify("s-1", 3).integrity_ok is False
    assert g1.status("s-1", 3).posture == "degraded"  # tamper is data
    assert g2.verify("s-1", 3).integrity_ok is True  # other instance clean


# 15. main() subprocess check + 8-thread read smoke + frozen-ness
def test_main_and_concurrency():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=str(MOD.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "assistance-game OK: play, evaluate, verify, retire, pins, audit"
    )

    g = _led()
    g.play("s-1", 1)
    g.evaluate("s-1", 2, value=50)
    results = []

    def worker():
        results.append(g.verify("s-1", 3).posture)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == ["improved"] * 8
    rec = g.play_record("ply-1", 3)
    with pytest.raises(Exception):
        rec.session_digest = _digest()  # frozen
