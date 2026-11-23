"""Targeted tests for hipaa.py (15 tests)."""

from __future__ import annotations

import ast
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import hipaa as hp

DIGEST = "sha256:" + "ab" * 32
DIGEST2 = "sha256:" + "cd" * 32


def make() -> hp.HIPAA:
    return hp.HIPAA()


def test_version_and_schema_pins():
    assert hp.HIPAA_VERSION == "hipaa.v1"
    assert hp.SCHEMA_PIN == "northstar.hipaa.v1"
    assert hp.AUDIT_SCHEMA == "audit.ndjson/1"
    assert hp.ENTITY_COVERED == "covered-entity"
    assert hp.ENTITY_ASSOCIATE == "business-associate"
    assert hp.CAT_ADMINISTRATIVE == "administrative"
    assert hp.CAT_PHYSICAL == "physical"
    assert hp.CAT_TECHNICAL == "technical"
    assert hp.FINDING_SATISFIED == "satisfied"
    assert hp.FINDING_NOT_SATISFIED == "not-satisfied"
    assert hp.ACTION_PATCH == "patch"


def test_stdlib_only():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                        "hipaa.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    allowed = {"hashlib", "threading", "dataclasses", "typing",
               "__future__", "canonical_json", "json"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= allowed, imported


def test_register_roundtrip_and_verify():
    h = make()
    rec = h.register_entity("org-1", 1, hp.ENTITY_COVERED, DIGEST)
    assert rec.entity_id == "org-1"
    assert rec.entity_kind == hp.ENTITY_COVERED
    assert rec.verify("org-1", hp.ENTITY_COVERED, DIGEST) is True
    assert rec.verify("org-1", hp.ENTITY_ASSOCIATE, DIGEST) is False
    assert rec.verify("org-1", hp.ENTITY_COVERED, DIGEST2) is False
    assert h.entity_record("org-1", 2) is rec
    assert h.entity_ids(3) == ("org-1",)
    assert h.stats(4)["entities"] == 1


def test_register_bad_inputs_and_seq_burn():
    h = make()
    n_rejected = 0
    cases = [
        (lambda s: h.register_entity("", s), hp.BadIdError),
        (lambda s: h.register_entity("  ", s), hp.BadIdError),
        (lambda s: h.register_entity("a" * 257, s), hp.BadIdError),
        (lambda s: h.register_entity(None, s), hp.BadIdError),
        (lambda s: h.register_entity(123, s), hp.BadIdError),
        (lambda s: h.register_entity("org-1", s, "other-kind"),
         hp.BadEntityKindError),
        (lambda s: h.register_entity("org-1", s, hp.ENTITY_COVERED,
                                      "not-a-digest"), hp.BadDigestError),
        (lambda s: h.register_entity("org-1", s, hp.ENTITY_COVERED,
                                      "sha256:" + "zz" * 32),
         hp.BadDigestError),
    ]
    seq = 1
    for fn, exc in cases:
        with pytest.raises(exc):
            fn(seq)
        n_rejected += 1
        seq += 1
    assert h.stats(seq)["rejected"] == n_rejected
    # duplicate burns too
    h.register_entity("org-1", seq)
    seq += 1
    with pytest.raises(hp.DuplicateEntityError):
        h.register_entity("org-1", seq)
    assert h.stats(seq + 1)["rejected"] == n_rejected + 1
    # all kinds accepted
    seq += 2
    h.register_entity("ba-1", seq, hp.ENTITY_ASSOCIATE)
    h.register_entity("sub-1", seq + 1, hp.ENTITY_SUBCONTRACTOR, DIGEST)
    assert h.entity_ids(seq + 2) == ("ba-1", "org-1", "sub-1")


def test_assess_roundtrip_and_vocabularies():
    h = make()
    h.register_entity("org-1", 1)
    a1 = h.assess("org-1", "164.308(a)(1)", hp.CAT_ADMINISTRATIVE, 2)
    a2 = h.assess("org-1", "164.310(a)(1)", hp.CAT_PHYSICAL, 3,
                  hp.FINDING_NOT_SATISFIED, DIGEST)
    a3 = h.assess("org-1", "164.312(a)(2)(iv)", hp.CAT_TECHNICAL, 4,
                  hp.FINDING_PARTIAL, DIGEST2)
    a4 = h.assess("org-1", "164.308(a)(7)", hp.CAT_ADMINISTRATIVE, 5,
                  hp.FINDING_NA)
    assert (a1.assessment_id, a2.assessment_id, a3.assessment_id,
            a4.assessment_id) == ("asm-1", "asm-2", "asm-3", "asm-4")
    assert a2.verify("org-1", "164.310(a)(1)", hp.CAT_PHYSICAL,
                     hp.FINDING_NOT_SATISFIED, DIGEST) is True
    assert a2.verify("org-1", "164.310(a)(1)", hp.CAT_TECHNICAL,
                     hp.FINDING_NOT_SATISFIED, DIGEST) is False
    assert h.assessments_for("org-1", 6) == ("asm-1", "asm-2", "asm-3",
                                             "asm-4")
    assert h.assessment_record("asm-3", 7) is a3
    assert h.stats(8)["assessments"] == 4


def test_assess_bad_inputs_and_seq_burn():
    h = make()
    h.register_entity("org-1", 1)
    n_rejected = 0
    cases = [
        (lambda s: h.assess("nope", "164.308", hp.CAT_ADMINISTRATIVE, s),
         hp.UnknownEntityError),
        (lambda s: h.assess("org-1", "164.308", "legal", s),
         hp.BadCategoryError),
        (lambda s: h.assess("org-1", "164.308", hp.CAT_ADMINISTRATIVE, s,
                            "maybe"), hp.BadFindingError),
        (lambda s: h.assess("org-1", "", hp.CAT_ADMINISTRATIVE, s),
         hp.BadIdError),
        (lambda s: h.assess("org-1", "164.308", hp.CAT_ADMINISTRATIVE, s,
                            hp.FINDING_SATISFIED, "raw-evidence"),
         hp.BadDigestError),
    ]
    seq = 2
    for fn, exc in cases:
        with pytest.raises(exc):
            fn(seq)
        n_rejected += 1
        seq += 1
    assert h.stats(seq)["rejected"] == n_rejected
    assert h.stats(seq)["assessments"] == 0


def test_remediate_roundtrip_and_verify():
    h = make()
    h.register_entity("org-1", 1)
    h.assess("org-1", "164.312(a)(2)(iv)", hp.CAT_TECHNICAL, 2,
             hp.FINDING_NOT_SATISFIED)
    h.assess("org-1", "164.308(a)(1)", hp.CAT_ADMINISTRATIVE, 3,
             hp.FINDING_PARTIAL)
    r1 = h.remediate("asm-1", hp.ACTION_PATCH, 4, DIGEST)
    r2 = h.remediate("asm-2", hp.ACTION_TRAINING, 5)
    assert (r1.remediation_id, r2.remediation_id) == ("rmd-1", "rmd-2")
    assert r1.verify("asm-1", hp.ACTION_PATCH, DIGEST) is True
    assert r1.verify("asm-1", hp.ACTION_RECONFIGURE, DIGEST) is False
    assert h.stats(6)["remediations"] == 2


def test_remediate_refusals_and_seq_burn():
    h = make()
    h.register_entity("org-1", 1)
    h.assess("org-1", "164.308(a)(1)", hp.CAT_ADMINISTRATIVE, 2)
    h.assess("org-1", "164.312(a)(2)(iv)", hp.CAT_TECHNICAL, 3,
             hp.FINDING_NOT_SATISFIED)
    n_rejected = 0
    seq = 4
    with pytest.raises(hp.UnknownAssessmentError):
        h.remediate("asm-99", hp.ACTION_PATCH, seq)
    n_rejected += 1
    seq += 1
    # satisfied assessment is not unsatisfied
    with pytest.raises(hp.AssessmentNotUnsatisfiedError):
        h.remediate("asm-1", hp.ACTION_PATCH, seq)
    n_rejected += 1
    seq += 1
    h.remediate("asm-2", hp.ACTION_PATCH, seq)
    seq += 1
    with pytest.raises(hp.AlreadyRemediatedError):
        h.remediate("asm-2", hp.ACTION_PATCH, seq)
    n_rejected += 1
    seq += 1
    h.assess("org-1", "164.310(a)(1)", hp.CAT_PHYSICAL, seq,
             hp.FINDING_PARTIAL)
    seq += 1
    with pytest.raises(hp.BadActionError):
        h.remediate("asm-3", "pray", seq)
    n_rejected += 1
    assert h.stats(seq + 1)["rejected"] == n_rejected


def test_attest_posture_transitions():
    h = make()
    h.register_entity("org-1", 1)
    rep = h.attest("org-1", 2)
    assert rep.posture == "not-assessed"
    assert rep.verify("org-1", "not-assessed", 0, 0, 0, 0) is True
    h.assess("org-1", "164.308(a)(1)", hp.CAT_ADMINISTRATIVE, 3)
    rep = h.attest("org-1", 4)
    assert rep.posture == "compliant"
    assert (rep.n_assessments, rep.n_satisfied) == (1, 1)
    h.assess("org-1", "164.312(a)(2)(iv)", hp.CAT_TECHNICAL, 5,
             hp.FINDING_NOT_SATISFIED)
    rep = h.attest("org-1", 6)
    assert rep.posture == "non-compliant"
    assert (rep.n_unsatisfied, rep.n_remediated) == (1, 0)
    h.remediate("asm-2", hp.ACTION_RECONFIGURE, 7)
    rep = h.attest("org-1", 8)
    assert rep.posture == "compliant"
    assert rep.verify("org-1", "compliant", 2, 1, 1, 1) is True
    # not-applicable does not move the needle
    h.assess("org-1", "164.310(d)(2)(iii)", hp.CAT_PHYSICAL, 9,
             hp.FINDING_NA)
    rep = h.attest("org-1", 10)
    assert rep.posture == "compliant"
    assert rep.n_assessments == 3


def test_attest_pure_read_and_unknown_entity():
    h = make()
    h.register_entity("org-1", 1)
    h.assess("org-1", "164.308(a)(1)", hp.CAT_ADMINISTRATIVE, 2)
    n_rows = len(h.audit_log(3))
    rep = h.attest("org-1", 4)
    rep2 = h.attest("org-1", 4)  # same seq reused: pure read
    assert rep == rep2
    assert len(h.audit_log(5)) == n_rows  # no audit rows written
    assert h.stats(6)["rejected"] == 0
    with pytest.raises(hp.UnknownEntityError):
        h.attest("ghost", 7)


def test_seq_discipline():
    h = make()
    h.register_entity("org-1", 1)
    # rewind raises bare: no rejected row, seq still claimed
    with pytest.raises(hp.SeqOrderError):
        h.register_entity("org-2", 1)
    with pytest.raises(hp.SeqOrderError):
        h.register_entity("org-2", 0)
    assert h.stats(2)["rejected"] == 0
    assert h.entity_ids(2) == ("org-1",)
    # malformed seqs raise bare too
    for bad in (True, "2", 1.5, None):
        with pytest.raises(hp.SeqOrderError):
            h.register_entity("org-2", bad)
    assert h.stats(2)["rejected"] == 0
    # failed mutation consumes its seq
    with pytest.raises(hp.DuplicateEntityError):
        h.register_entity("org-1", 2)
    assert h.stats(3)["rejected"] == 1
    # reads only shape-validate: a rewound seq on a pure read does not raise
    rep = h.attest("org-1", 2)
    assert rep.posture == "not-assessed"
    assert h.stats(3)["rejected"] == 1  # no new rejected rows
    with pytest.raises(hp.SeqOrderError):
        h.stats(-1)  # malformed seq on a read still raises bare


def test_audit_shapes_and_leak_ban_and_bad_kind():
    h = make()
    h.register_entity("org-1", 1, hp.ENTITY_ASSOCIATE)
    h.assess("org-1", "164.308(a)(1)", hp.CAT_ADMINISTRATIVE, 2,
             hp.FINDING_NOT_SATISFIED)
    h.remediate("asm-1", hp.ACTION_DOCUMENT, 3)
    rows = h.audit_log(4)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["hipaa.registered", "hipaa.assessed", "hipaa.remediated"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "hipaa.v1"
        assert set(r) == {"schema", "module", "kind", "seq", "detail"}
    # banned keys rejected at the builder level
    for bad_key in ("phi", "ephi", "profile", "evidence", "text",
                    "description"):
        with pytest.raises(hp.AuditKindError):
            hp.hipaa_audit_event("hipaa.assessed", {bad_key: "x"}, 9)
    with pytest.raises(hp.AuditKindError):
        hp.hipaa_audit_event("hipaa.nope", {}, 9)
    with pytest.raises(hp.SeqOrderError):
        hp.hipaa_audit_event("hipaa.assessed", {}, "9")
    # detail is copied, not aliased
    detail = {"entity_id": "org-1"}
    row = hp.hipaa_audit_event("hipaa.registered", detail, 9)
    detail["entity_id"] = "tampered"
    assert row["detail"]["entity_id"] == "org-1"


def test_cross_instance_determinism_and_tamper():
    h1, h2 = make(), make()
    r1 = h1.register_entity("org-1", 1, hp.ENTITY_COVERED, DIGEST)
    r2 = h2.register_entity("org-1", 1, hp.ENTITY_COVERED, DIGEST)
    assert r1.digest == r2.digest
    a1 = h1.assess("org-1", "164.312", hp.CAT_TECHNICAL, 2,
                   hp.FINDING_SATISFIED, DIGEST)
    a2 = h2.assess("org-1", "164.312", hp.CAT_TECHNICAL, 2,
                   hp.FINDING_SATISFIED, DIGEST)
    assert a1.digest == a2.digest
    # tamper breaks verify: verify() recomputes the pin from its arguments,
    # so corrupt the stored digest to detect tampering
    assert a1.verify("org-1", "164.312", hp.CAT_TECHNICAL,
                     hp.FINDING_SATISFIED, DIGEST) is True
    object.__setattr__(a1, "digest", "sha256:" + "ff" * 32)
    assert a1.verify("org-1", "164.312", hp.CAT_TECHNICAL,
                     hp.FINDING_SATISFIED, DIGEST) is False
    assert a1.verify("org-1", "164.312", hp.CAT_PHYSICAL,
                     hp.FINDING_SATISFIED, DIGEST) is False
    with pytest.raises(AttributeError):
        r1.entity_id = "other"
    assert r1.digest == r2.digest


def test_read_purity_stats_and_views():
    h = make()
    h.register_entity("org-1", 1)
    h.assess("org-1", "164.308(a)(1)", hp.CAT_ADMINISTRATIVE, 2,
             hp.FINDING_NOT_SATISFIED)
    rows_before = len(h.audit_log(3))
    assert h.entity_record("org-1", 4).entity_kind == hp.ENTITY_COVERED
    assert h.assessment_record("asm-1", 4).finding == \
        hp.FINDING_NOT_SATISFIED
    assert h.entity_ids(4) == ("org-1",)
    assert h.assessments_for("org-1", 4) == ("asm-1",)
    assert h.stats(4) == {"entities": 1, "assessments": 1, "remediations": 0,
                          "rejected": 0}
    assert len(h.audit_log(5)) == rows_before  # reads add nothing
    with pytest.raises(hp.UnknownAssessmentError):
        h.assessment_record("asm-99", 6)
    with pytest.raises(hp.UnknownEntityError):
        h.entity_record("ghost", 6)
    with pytest.raises(hp.UnknownEntityError):
        h.assessments_for("ghost", 6)
    # reads only shape-validate: a rewound seq on a pure read is fine
    assert h.entity_ids(2) == ("org-1",)


def test_main_subprocess():
    mod = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                       "hipaa.py")
    out = subprocess.run([sys.executable, mod], capture_output=True,
                         text=True, check=False)
    assert out.returncode == 0, out.stderr
    assert "hipaa OK: register, assess, remediate, attest, pins, audit" in \
        out.stdout
