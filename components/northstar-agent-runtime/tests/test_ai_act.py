"""Tests for the EU AI Act governance decision ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_act.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_act", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_act"] = module
    spec.loader.exec_module(module)
    return module


ai_act = _load()


# 1. version/schema pins + vocabulary
def test_version_and_schema_pins():
    assert ai_act.AI_ACT_VERSION == "ai-act.v1"
    assert ai_act.SCHEMA_PIN == "northstar.ai-act.v1"
    assert ai_act.RISK_CLASSES == (
        "prohibited",
        "high-risk",
        "limited-risk",
        "minimal-risk",
        "gpaI-model",
        "gpaI-model-systemic",
    )
    assert ai_act.CONFORMITY_OUTCOMES == (
        "conform",
        "non-conform",
        "conditional",
        "not-applicable",
    )
    assert ai_act.NOTIFY_CHANNELS == (
        "eu-database",
        "market-surveillance",
        "notified-body",
        "deployers",
        "internal",
    )
    assert ai_act.NOTIFY_REASONS == (
        "serious-incident",
        "market-entry",
        "fundamental-rights-impact",
        "withdrawal",
        "manual",
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


# 3. classify roundtrip + verify
def test_classify_roundtrip():
    a = ai_act.AIAct()
    rec = a.classify("sys-1", "high-risk", 1, system_digest=PIN)
    assert rec.system_id == "sys-1"
    assert rec.risk_class == "high-risk"
    assert rec.system_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == ai_act.SCHEMA_PIN
    got = a.classification_record("sys-1", 0)
    assert got.verify()
    # all risk classes accepted
    for i, rc in enumerate(ai_act.RISK_CLASSES[1:], start=1):
        r = a.classify(f"sys-r{i}", rc, i + 1)
        assert r.risk_class == rc and r.verify()


# 4. classify duplicate + bad-input table with seq-burn + rejected rows
def test_classify_refusals():
    a = ai_act.AIAct()
    a.classify("sys-1", "high-risk", 1)
    seq = 1
    rejected = 0
    with pytest.raises(ai_act.DuplicateSystemError):
        seq += 1
        a.classify("sys-1", "high-risk", seq)
    rejected += 1
    with pytest.raises(ai_act.BadRiskClassError):
        seq += 1
        a.classify("sys-x", "doomsday", seq)
    rejected += 1
    with pytest.raises(ai_act.BadDigestError):
        seq += 1
        a.classify("sys-x", "high-risk", seq, system_digest="not-a-pin")
    rejected += 1
    with pytest.raises(ai_act.BadSystemError):
        seq += 1
        a.classify("", "high-risk", seq)
    rejected += 1
    with pytest.raises(ai_act.BadSystemError):
        seq += 1
        a.classify(None, "high-risk", seq)
    rejected += 1
    rows = a.audit_log(0)
    rej_rows = [r for r in rows if r["kind"] == "rejected"]
    assert len(rej_rows) == rejected
    assert a.stats(0)["systems"] == 1
    # duplicate refused before consumption by any other success
    assert a.classification_record("sys-1", 0).risk_class == "high-risk"


# 5. conform roundtrip + minted ids + verify
def test_conform_roundtrip():
    a = ai_act.AIAct()
    a.classify("sys-1", "high-risk", 1)
    cnf1 = a.conform("sys-1", 2, outcome="non-conform", evidence_digest=PIN)
    assert cnf1.conformity_id == "cnf-1"
    assert cnf1.outcome == "non-conform"
    assert cnf1.evidence_digest == PIN
    assert cnf1.verify()
    cnf2 = a.conform("sys-1", 3)
    assert cnf2.conformity_id == "cnf-2"
    assert cnf2.outcome == "conform"
    assert cnf2.verify()
    for i, out in enumerate(ai_act.CONFORMITY_OUTCOMES[2:], start=4):
        c = a.conform("sys-1", i, outcome=out)
        assert c.verify()
    assert a.conformity_record("cnf-1", 0).verify()


# 6. conform bad-input table + seq-burn + rejected rows
def test_conform_refusals():
    a = ai_act.AIAct()
    a.classify("sys-1", "high-risk", 1)
    seq = 1
    rejected = 0
    with pytest.raises(ai_act.UnknownSystemError):
        seq += 1
        a.conform("ghost", seq)
    rejected += 1
    with pytest.raises(ai_act.BadOutcomeError):
        seq += 1
        a.conform("sys-1", seq, outcome="maybe")
    rejected += 1
    with pytest.raises(ai_act.BadDigestError):
        seq += 1
        a.conform("sys-1", seq, evidence_digest="sha256:zzz")
    rejected += 1
    rej_rows = [r for r in a.audit_log(0) if r["kind"] == "rejected"]
    assert len(rej_rows) == rejected
    assert a.stats(0)["conformities"] == 0


# 7. notify roundtrip across all channels + reasons
def test_notify_roundtrip():
    a = ai_act.AIAct()
    a.classify("sys-1", "high-risk", 1)
    seq = 1
    for channel in ai_act.NOTIFY_CHANNELS:
        for reason in ai_act.NOTIFY_REASONS:
            seq += 1
            n = a.notify("sys-1", seq, channel=channel, reason=reason)
            assert n.verify()
    assert len(ai_act.NOTIFY_CHANNELS) * len(ai_act.NOTIFY_REASONS) == 25
    assert a.stats(0)["notifications"] == 25
    n1 = a.notification_record("ntf-1", 0)
    assert n1.channel == "eu-database" and n1.reason == "serious-incident"
    ids = a.notifications_for("sys-1", 0)
    assert ids == tuple(f"ntf-{i}" for i in range(1, 26))


# 8. notify bad-input table + seq-burn
def test_notify_refusals():
    a = ai_act.AIAct()
    a.classify("sys-1", "high-risk", 1)
    seq = 1
    rejected = 0
    with pytest.raises(ai_act.UnknownSystemError):
        seq += 1
        a.notify("ghost", seq)
    rejected += 1
    with pytest.raises(ai_act.BadChannelError):
        seq += 1
        a.notify("sys-1", seq, channel="carrier-pigeon")
    rejected += 1
    with pytest.raises(ai_act.BadReasonError):
        seq += 1
        a.notify("sys-1", seq, reason="vibes")
    rejected += 1
    rej_rows = [r for r in a.audit_log(0) if r["kind"] == "rejected"]
    assert len(rej_rows) == rejected
    assert a.stats(0)["notifications"] == 0


# 9. posture math + integrity + unknown
def test_posture():
    a = ai_act.AIAct()
    a.classify("sys-1", "high-risk", 1, system_digest=PIN)
    p = a.posture("sys-1", 0)
    assert p.verify()
    assert p.risk_class == "high-risk"
    assert p.latest_outcome == "not-assessed"
    assert p.n_conformities == 0 and p.n_notifications == 0
    assert p.integrity_ok
    a.conform("sys-1", 2, outcome="non-conform")
    a.conform("sys-1", 3, outcome="conform")
    a.notify("sys-1", 4, channel="market-surveillance", reason="serious-incident")
    p = a.posture("sys-1", 0)
    assert p.verify()
    assert p.n_conformities == 2
    assert p.latest_outcome == "conform"
    assert p.n_notifications == 1
    assert p.integrity_ok
    with pytest.raises(ai_act.UnknownSystemError):
        a.posture("ghost", 0)


# 10. seq discipline: rewind raises bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    a = ai_act.AIAct()
    a.classify("sys-1", "high-risk", 5)
    # rewind raises bare and consumes nothing
    with pytest.raises(ai_act.SeqOrderError):
        a.classify("sys-2", "high-risk", 5)
    with pytest.raises(ai_act.SeqOrderError):
        a.conform("sys-1", 4)
    assert a.stats(0)["systems"] == 1
    for bad in (True, "6", None, -1, 0):
        with pytest.raises(ai_act.SeqOrderError):
            a.classify("sys-x", "high-risk", bad)
    # failed mutation consumed the seq: next valid call must be higher
    with pytest.raises(ai_act.SeqOrderError):
        a.classify("sys-3", "high-risk", 5)
    r = a.classify("sys-3", "minimal-risk", 6)
    assert r.verify()


# 11. view read-purity: same seq twice, no audit rows, nothing consumed
def test_view_read_purity():
    a = ai_act.AIAct()
    a.classify("sys-1", "high-risk", 1)
    a.conform("sys-1", 2)
    n_rows = a.stats(0)["audit_rows"]
    for _ in range(3):
        assert a.posture("sys-1", 0).verify()
        assert a.classification_record("sys-1", 0).verify()
        assert a.system_ids(0) == ("sys-1",)
        assert a.conformity_ids(0) == ("cnf-1",)
        assert a.conformities_for("sys-1", 0) == ("cnf-1",)
        assert a.stats(0) == {
            "systems": 1,
            "conformities": 1,
            "notifications": 0,
            "audit_rows": n_rows,
        }
    assert a.stats(0)["audit_rows"] == n_rows
    with pytest.raises(ai_act.UnknownSystemError):
        a.conformities_for("ghost", 0)
    with pytest.raises(ai_act.UnknownConformityError):
        a.conformity_record("cnf-9", 0)
    with pytest.raises(ai_act.UnknownNotificationError):
        a.notification_record("ntf-9", 0)
    # view seqs are shape-checked but never consumed: seq=0 ok, negatives raise
    with pytest.raises(ai_act.SeqOrderError):
        a.stats(-1)
    with pytest.raises(ai_act.SeqOrderError):
        a.stats("0")


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    a = ai_act.AIAct()
    a.classify("sys-1", "high-risk", 1, system_digest=PIN)
    a.conform("sys-1", 2)
    a.notify("sys-1", 3, channel="eu-database", reason="market-entry")
    rows = a.audit_log(0)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["classified", "assessed", "notified"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
    # audit builder: bad kind
    with pytest.raises(ai_act.AuditKindError):
        ai_act.ai_act_audit_event("classified-wrong", 4)
    # audit builder: banned raw keys
    for banned in ("system_name", "description", "model", "payload", "deployer"):
        with pytest.raises(ai_act.AuditKindError):
            ai_act.ai_act_audit_event("classified", 4, **{banned: "x"})
    # pinned vocabulary values remain emittable as declared data
    ok = ai_act.ai_act_audit_event("classified", 4, risk_class="high-risk")
    assert ok["details"]["risk_class"] == "high-risk"
    # no raw keys anywhere in the audit log
    banned = ai_act._BANNED_AUDIT_KEYS
    for r in rows:
        assert not (set(r["details"]) & banned)


# 13. cross-instance digest determinism + tamper breaks verify
def test_digest_determinism_and_tamper():
    b1, b2 = ai_act.AIAct(), ai_act.AIAct()
    r1 = b1.classify("sys-1", "high-risk", 1, system_digest=PIN)
    r2 = b2.classify("sys-1", "high-risk", 1, system_digest=PIN)
    assert r1.digest == r2.digest
    c1 = b1.conform("sys-1", 2, outcome="conform", evidence_digest=PIN2)
    c2 = b2.conform("sys-1", 2, outcome="conform", evidence_digest=PIN2)
    assert c1.digest == c2.digest
    assert c1.verify() and c2.verify()
    import dataclasses

    object.__setattr__(r1, "risk_class", "minimal-risk")
    assert not r1.verify()
    object.__setattr__(c1, "outcome", "non-conform")
    assert not c1.verify()


# 14. frozen-ness + threaded read smoke
def test_frozen_and_threaded():
    import dataclasses

    a = ai_act.AIAct()
    rec = a.classify("sys-1", "high-risk", 1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.risk_class = "minimal-risk"
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.system_digest = PIN
    cnf = a.conform("sys-1", 2)
    with pytest.raises(dataclasses.FrozenInstanceError):
        cnf.outcome = "non-conform"
    ntf = a.notify("sys-1", 3)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ntf.channel = "internal"
    st = a.posture("sys-1", 0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        st.n_conformities = 99

    errors = []

    def reader():
        try:
            for _ in range(50):
                assert a.posture("sys-1", 0).verify()
                assert a.system_ids(0) == ("sys-1",)
                assert a.stats(0)["systems"] == 1
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 15. main() subprocess check + standalone import
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(MOD.parent),
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ai-act OK: classify, conform, notify, posture, pins"
