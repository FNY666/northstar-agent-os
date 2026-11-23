"""Tests for the transparency-obligation disclosure ledger (Simulated)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "transparency.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("transparency", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["transparency"] = module
    spec.loader.exec_module(module)
    return module


tr = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert tr.TRANSPARENCY_VERSION == "transparency.v1"
    assert tr.SCHEMA_PIN == "northstar.transparency.v1"
    assert tr.SUBJECTS == ("ai-model", "ai-system", "generated-content", "dataset", "agent")
    assert tr.KINDS == (
        "ai-interaction",
        "ai-generated-content",
        "capability-limits",
        "training-data-summary",
        "watermarking",
        "human-oversight",
        "contact-point",
        "risk-warning",
    )
    assert tr.VERDICTS == ("complete", "partial", "stale")
    assert tr.RETRACT_REASONS == ("manual", "superseded", "erroneous", "revoked")
    assert tr.AUDIT_KINDS == ("disclosed", "retracted", "rejected")


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


# 3. disclose roundtrip + record verify
def test_disclose_roundtrip():
    t = tr.Transparency()
    rec = t.disclose(
        "TR-1",
        "ai-system",
        1,
        disclosure_kind="ai-interaction",
        subject_digest=PIN,
        content_digest=PIN2,
    )
    assert rec.disclosure_id == "TR-1"
    assert rec.subject == "ai-system"
    assert rec.disclosure_kind == "ai-interaction"
    assert rec.verify()
    assert t.disclosure_record("TR-1", 0).verify()
    rows = t.audit_log(0)
    assert rows[-1]["kind"] == "disclosed"
    assert rows[-1]["details"]["disclosure_id"] == "TR-1"
    assert rows[-1]["details"]["subject"] == "ai-system"


# 4. duplicate + bad-input table + seq-burn + rejected rows
def test_disclose_bad_inputs_and_seq_burn():
    t = tr.Transparency()
    t.disclose("TR-1", "ai-model", 1)
    seq = 2
    with pytest.raises(tr.DuplicateDisclosureError):
        t.disclose("TR-1", "ai-model", seq)
    seq += 1
    with pytest.raises(tr.BadIdError):
        t.disclose("", "ai-model", seq)
    seq += 1
    with pytest.raises(tr.BadSubjectError):
        t.disclose("TR-2", "blockchain", seq)
    seq += 1
    with pytest.raises(tr.BadKindError):
        t.disclose("TR-2", "ai-model", seq, disclosure_kind="financial-advice")
    seq += 1
    with pytest.raises(tr.BadDigestError):
        t.disclose("TR-2", "ai-model", seq, subject_digest="nope")
    # every failed mutation consumed its seq and booked a rejected row
    assert t.stats(0)["seq"] == seq
    rows = t.audit_log(0)
    assert len([r for r in rows if r["kind"] == "rejected"]) == 5
    # seq is burned: reusing it rewinds bare with no new row
    with pytest.raises(tr.SeqOrderError):
        t.disclose("TR-3", "ai-model", seq)
    assert len([r for r in t.audit_log(0) if r["kind"] == "rejected"]) == 5


# 5. full subject x kind vocabulary acceptance
def test_full_vocabulary_acceptance():
    t = tr.Transparency()
    seq = 0
    ids = []
    for subject in tr.SUBJECTS:
        for kind in tr.KINDS:
            seq += 1
            did = f"TR-{subject}-{kind}"
            rec = t.disclose(did, subject, seq, disclosure_kind=kind)
            assert rec.verify()
            ids.append(did)
    assert len(ids) == len(tr.SUBJECTS) * len(tr.KINDS)
    rep = t.audit(0)
    assert rep.n_disclosures == len(ids)
    assert dict(rep.subject_tallies) == {s: len(tr.KINDS) for s in tr.SUBJECTS}
    assert dict(rep.kind_tallies) == {k: len(tr.SUBJECTS) for k in tr.KINDS}


# 6. verify roundtrip: complete verdict + read purity
def test_verify_roundtrip_complete_and_read_purity():
    t = tr.Transparency()
    t.disclose("TR-1", "generated-content", 1, disclosure_kind="ai-generated-content",
               subject_digest=PIN, content_digest=PIN2)
    before = len(t.audit_log(0))
    v1 = t.verify("TR-1", 0)
    v2 = t.verify("TR-1", 0)
    assert v1.verify() and v2.verify()
    assert v1.verdict == "complete"
    assert v1.integrity_ok is True
    assert all(ok for _, ok in v1.checks)
    assert dict(v1.checks)["not-retracted"] is True
    assert len(t.audit_log(0)) == before  # no audit rows on reads
    assert t.stats(0)["seq"] == 1  # reads never consume seq


# 7. verify unknown refused with seq burn
def test_verify_unknown_refused():
    t = tr.Transparency()
    t.disclose("TR-1", "agent", 1)
    with pytest.raises(tr.UnknownDisclosureError):
        t.verify("NOPE", 0)
    # view reads do not consume seq and write no rows
    assert t.stats(0)["seq"] == 1
    assert len([r for r in t.audit_log(0) if r["kind"] == "rejected"]) == 0


# 8. verify stale after retract (verdict as data)
def test_verify_stale_after_retract():
    t = tr.Transparency()
    t.disclose("TR-1", "dataset", 1, disclosure_kind="training-data-summary")
    r = t.retract("TR-1", 2, reason="superseded")
    assert r.verify()
    assert t.retraction_record("TR-1", 0).verify()
    v = t.verify("TR-1", 0)
    assert v.verify()
    assert v.verdict == "stale"
    assert v.integrity_ok is True  # ledger record itself is intact
    assert dict(v.checks)["not-retracted"] is False
    assert t.retracted_ids(0) == ("TR-1",)
    assert t.active_ids(0) == ()


# 9. tamper breaks integrity -> partial verdict as data
def test_verify_tamper_partial():
    t = tr.Transparency()
    rec = t.disclose("TR-1", "ai-model", 1, disclosure_kind="capability-limits")
    object.__setattr__(rec, "subject", "bogus")
    assert rec.verify() is False
    v = t.verify("TR-1", 0)
    assert v.verdict == "partial"
    assert v.integrity_ok is False
    assert dict(v.checks)["digest-pins-valid"] is False
    # the aggregate audit flags integrity as data too
    rep = t.audit(0)
    assert rep.integrity_ok is False
    assert rep.verify()


# 10. retract terminality + all reasons + id non-recycling + bad reason
def test_retract_terminality():
    t = tr.Transparency()
    t.disclose("TR-1", "ai-system", 1)
    wd = t.retract("TR-1", 2, reason="erroneous")
    assert wd.reason == "erroneous"
    assert wd.verify()
    # post-retract mutations refused
    with pytest.raises(tr.RetiredDisclosureError):
        t.retract("TR-1", 3)
    with pytest.raises(tr.RetiredDisclosureError):
        t.disclose("TR-1", "ai-system", 4)
    # reads still work
    assert t.verify("TR-1", 0).verdict == "stale"
    # all 4 reasons accepted
    seq = 4
    for i, reason in enumerate(tr.RETRACT_REASONS):
        did = f"R-{i}"
        seq += 1
        t.disclose(did, "agent", seq, disclosure_kind="contact-point")
        seq += 1
        t.retract(did, seq, reason=reason)
    assert t.stats(0)["retracted"] == 5
    # bad reason refused with seq burn
    seq += 1
    t.disclose("TR-9", "ai-model", seq)
    with pytest.raises(tr.BadReasonError):
        t.retract("TR-9", seq + 1, reason="bogus")


# 11. audit math + scoped audit + unknown-scoped-as-data + read purity
def test_audit_math_and_scoped():
    t = tr.Transparency()
    t.disclose("A-1", "ai-model", 1, disclosure_kind="watermarking")
    t.disclose("A-2", "ai-model", 2, disclosure_kind="human-oversight")
    t.disclose("B-1", "dataset", 3, disclosure_kind="training-data-summary")
    t.retract("B-1", 4, reason="manual")
    before = len(t.audit_log(0))
    rep = t.audit(0)
    assert rep.verify()
    assert rep.n_disclosures == 3
    assert rep.n_active == 2
    assert rep.n_retracted == 1
    assert dict(rep.subject_tallies) == {"ai-model": 2, "dataset": 1}
    assert dict(rep.kind_tallies) == {
        "watermarking": 1,
        "human-oversight": 1,
        "training-data-summary": 1,
    }
    assert rep.integrity_ok is True
    # scoped audit
    scoped = t.audit(0, disclosure_id="A-1")
    assert scoped.n_disclosures == 1 and scoped.n_active == 1
    assert scoped.verify()
    # unknown scope yields an empty report as data, never raised
    empty = t.audit(0, disclosure_id="NOPE")
    assert empty.n_disclosures == 0 and empty.verify()
    assert len(t.audit_log(0)) == before  # reads write no rows


# 12. seq discipline (rewind bare, malformed seqs, failed-mutation-consumes-seq)
def test_seq_discipline():
    t = tr.Transparency()
    t.disclose("TR-1", "ai-system", 1)
    n_rejected = len([r for r in t.audit_log(0) if r["kind"] == "rejected"])
    # rewind raises bare: no seq burn, no rejected row
    with pytest.raises(tr.SeqOrderError):
        t.disclose("TR-2", "ai-system", 1)
    assert t.stats(0)["seq"] == 1
    assert len([r for r in t.audit_log(0) if r["kind"] == "rejected"]) == n_rejected
    # malformed seqs raise bare too
    for bad in (True, "2", 0, -1, 1.5, None):
        with pytest.raises(tr.SeqOrderError):
            t.disclose("TR-X", "ai-system", bad)
    assert t.stats(0)["seq"] == 1
    # failed mutation consumes its seq
    with pytest.raises(tr.DuplicateDisclosureError):
        t.disclose("TR-1", "ai-system", 2)
    assert t.stats(0)["seq"] == 2


# 13. audit shapes + 24-key leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    t = tr.Transparency()
    t.disclose("TR-1", "ai-system", 1, disclosure_kind="ai-interaction")
    t.disclose("TR-2", "generated-content", 2, disclosure_kind="ai-generated-content")
    t.retract("TR-2", 3, reason="manual")
    rows = t.audit_log(0)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["disclosed", "disclosed", "retracted"]
    banned = {
        "content", "text", "prompt", "response", "output", "training",
        "training_data", "dataset", "weights", "document", "details",
        "summary", "user", "username", "email", "name", "personal", "pii",
        "secret", "raw", "payload", "value", "data", "input",
    }
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["seq"] >= 1
        assert not (set(r["details"]) & banned)
    # banned raw keys refused at the builder boundary
    for key in banned:
        with pytest.raises(tr.AuditKindError):
            tr.transparency_audit_event("disclosed", 1, **{key: "x"})
    with pytest.raises(tr.AuditKindError):
        tr.transparency_audit_event("bogus-kind", 1)


# 14. cross-instance digest determinism + views + stats + frozen-ness
def test_digest_determinism_and_views():
    a = tr.Transparency()
    b = tr.Transparency()
    ra = a.disclose("TR-1", "ai-model", 1, disclosure_kind="risk-warning",
                    subject_digest=PIN)
    rb = b.disclose("TR-1", "ai-model", 1, disclosure_kind="risk-warning",
                    subject_digest=PIN)
    assert ra.digest == rb.digest
    va = a.verify("TR-1", 0)
    vb = b.verify("TR-1", 0)
    assert va.digest == vb.digest
    # different content -> different pin
    c = tr.Transparency()
    rc = c.disclose("TR-1", "ai-model", 1, disclosure_kind="risk-warning",
                    subject_digest=PIN2)
    assert rc.digest != rb.digest
    # views and stats
    assert a.disclosure_ids(0) == ("TR-1",)
    assert a.active_ids(0) == ("TR-1",)
    assert a.retracted_ids(0) == ()
    stats = a.stats(0)
    assert stats["disclosures"] == 1
    assert stats["active"] == 1
    assert stats["retracted"] == 0
    assert stats["audit_rows"] == 1
    assert stats["seq"] == 1
    with pytest.raises(tr.UnknownDisclosureError):
        a.disclosure_record("NOPE", 0)
    with pytest.raises(tr.UnknownDisclosureError):
        a.retraction_record("TR-1", 0)
    # frozen-ness
    with pytest.raises(Exception):
        ra.subject = "ai-system"


# 15. main() subprocess check
def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert "transparency OK" in result.stdout
