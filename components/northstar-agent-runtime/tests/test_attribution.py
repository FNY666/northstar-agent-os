"""Tests for attribution.py — source-attribution bookkeeping."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import attribution
from attribution import (
    AUDIT_KINDS,
    LINK_METHODS,
    SCHEMA,
    SOURCE_KINDS,
    VERSION,
    Attribution,
    AttributionError,
    AuditKindError,
    BadConfidenceError,
    BadDigestError,
    DuplicateLinkError,
    DuplicateSourceError,
    RetiredSourceError,
    SeqOrderError,
    UnknownLinkError,
    UnknownSourceError,
    attribution_audit_event,
)

COMP = Path(__file__).resolve().parent.parent


def test_01_version_and_schema_pins():
    assert attribution.VERSION == "attribution.v1"
    assert attribution.SCHEMA == "northstar.attribution.v1"
    assert VERSION == "attribution.v1"
    assert SCHEMA == "northstar.attribution.v1"
    assert "attribution.rejected" in AUDIT_KINDS
    assert len(SOURCE_KINDS) == 6
    assert len(LINK_METHODS) == 6


def test_02_stdlib_only_ast_check():
    src = (COMP / "attribution.py").read_text()
    tree = ast.parse(src)
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top in allowed, f"import {alias.name} not allowed"
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            assert top in allowed, f"from-import {node.module} not allowed"


def test_03_source_roundtrip_and_verify():
    at = Attribution()
    rec = at.source("claude-opus", "ai-model", 1)
    assert rec.source_id == "claude-opus"
    assert rec.kind == "ai-model"
    assert rec.detail_digest == ""
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    d = rec.as_dict()
    assert d["schema"] == SCHEMA and d["version"] == VERSION
    assert at.source_record("claude-opus", 2) == rec
    assert at.source_ids(3) == ("claude-opus",)
    log = at.audit_log(4)
    assert len(log) == 1 and log[0]["kind"] == "source-declared"
    # all six kinds accepted
    at2 = Attribution()
    for i, kind in enumerate(SOURCE_KINDS):
        at2.source(f"s-{i}", kind, i + 1)
    assert at2.stats(7)["sources"] == 6


def test_04_source_bad_inputs_seq_burn_and_rejected_rows():
    at = Attribution()
    bad = [
        ("", "ai-model"),  # empty id
        ("x" * 129, "organization"),  # too long
        (123, "organization"),  # non-str id
        (True, "organization"),  # bool id
        ("ok-id", "bogus-kind"),  # unknown kind
        ("ok-id", True),  # bool kind
        ("ok-id", "ai-model", 123),  # non-str detail digest
        ("ok-id", "ai-model", "zzz"),  # malformed digest pin
    ]
    seq = 0
    for entry in bad:
        seq += 1
        sid, kind = entry[0], entry[1]
        digest = entry[2] if len(entry) > 2 else ""
        with pytest.raises(AttributionError):
            at.source(sid, kind, seq, detail_digest=digest)
    log = at.audit_log(seq + 1)
    rejected = [e for e in log if e["kind"] == "attribution.rejected"]
    assert len(rejected) == len(bad)
    assert at.stats(seq + 2)["sources"] == 0
    assert at.stats(seq + 3)["seq"] == seq


def test_05_source_duplicate_refused():
    at = Attribution()
    at.source("s-1", "human-author", 1)
    with pytest.raises(DuplicateSourceError):
        at.source("s-1", "organization", 2)
    log = at.audit_log(3)
    assert sum(1 for e in log if e["kind"] == "attribution.rejected") == 1


def test_06_link_roundtrip_and_verify():
    at = Attribution()
    at.source("claude-opus", "ai-model", 1)
    pin = "sha256:" + "ab" * 32
    rec = at.link(
        "article-001", "claude-opus", 2, method="watermark", confidence=0.9,
        content_digest=pin,
    )
    assert rec.content_id == "article-001"
    assert rec.source_id == "claude-opus"
    assert rec.method == "watermark"
    assert rec.confidence == 0.9
    assert rec.content_digest == pin
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    d = rec.as_dict()
    assert d["schema"] == SCHEMA and d["version"] == VERSION
    assert at.link_record("article-001", 3) == rec
    assert at.link_ids(4) == ("article-001",)
    log = at.audit_log(5)
    kinds = [e["kind"] for e in log]
    assert kinds == ["source-declared", "linked"]
    # confidence ints accepted as float
    at.link("article-002", "claude-opus", 6, confidence=1)
    assert at.link_record("article-002", 7).confidence == 1.0


def test_07_link_bad_inputs_seq_burn():
    at = Attribution()
    at.source("s-1", "data-corpus", 1)
    seq = 1
    bad_calls = [
        lambda s: at.link("", "s-1", s),  # empty content id
        lambda s: at.link("c", "s-1", s, method="bogus"),  # bad method
        lambda s: at.link("c", "s-1", s, method=True),  # bool method
        lambda s: at.link("c", "s-1", s, confidence=True),  # bool confidence
        lambda s: at.link("c", "s-1", s, confidence=1.5),  # out of range
        lambda s: at.link("c", "s-1", s, confidence=float("nan")),  # NaN
        lambda s: at.link("c", "s-1", s, confidence=float("inf")),  # inf
        lambda s: at.link("c", "s-1", s, confidence="high"),  # str confidence
        lambda s: at.link("c", "s-1", s, content_digest="nope"),  # bad pin
        lambda s: at.link("c", "nope", s),  # unknown source
    ]
    for call in bad_calls:
        seq += 1
        with pytest.raises(AttributionError):
            call(seq)
    log = at.audit_log(seq + 1)
    rejected = [e for e in log if e["kind"] == "attribution.rejected"]
    assert len(rejected) == len(bad_calls)
    assert at.stats(seq + 2)["links"] == 0
    with pytest.raises(UnknownSourceError):
        at.source_record("nope", seq + 3)
    with pytest.raises(UnknownLinkError):
        at.link_record("nope", seq + 4)


def test_08_link_duplicate_content_refused():
    at = Attribution()
    at.source("s-1", "organization", 1)
    at.link("c-1", "s-1", 2)
    with pytest.raises(DuplicateLinkError):
        at.link("c-1", "s-1", 3)
    log = at.audit_log(4)
    assert sum(1 for e in log if e["kind"] == "attribution.rejected") == 1


def test_09_verify_attributed_report():
    at = Attribution()
    at.source("s-1", "human-author", 1)
    at.link("c-1", "s-1", 2, method="c2pa-manifest", confidence=0.75)
    rep = at.verify("c-1", 3)
    assert rep.content_id == "c-1"
    assert rep.source_id == "s-1"
    assert rep.source_kind == "human-author"
    assert rep.method == "c2pa-manifest"
    assert rep.confidence == 0.75
    assert rep.attributed is True
    assert rep.integrity_ok is True
    assert rep.digest.startswith("sha256:")
    assert rep.verify() is True
    d = rep.as_dict()
    assert d["schema"] == SCHEMA and d["version"] == VERSION


def test_10_verify_unknown_content_is_data():
    at = Attribution()
    rep = at.verify("never-seen", 1)
    assert rep.attributed is False
    assert rep.source_id == ""
    assert rep.source_kind == ""
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # read purity: same seq twice, no audit rows, no seq consumption
    rep2 = at.verify("never-seen", 1)
    assert rep2 == rep
    assert at.audit_log(2) == ()
    assert at.stats(3)["seq"] == 0


def test_11_verify_retired_source_broken():
    at = Attribution()
    at.source("s-1", "third-party", 1)
    at.link("c-1", "s-1", 2)
    assert at.verify("c-1", 3).attributed is True
    ret = at.retire("s-1", 4, reason="revoked")
    assert ret.verify() is True and ret.reason == "revoked"
    rep = at.verify("c-1", 5)
    assert rep.attributed is False
    assert rep.integrity_ok is True
    assert rep.source_kind == "third-party"
    assert at.retired_ids(6) == ("s-1",)
    # link to a retired source is refused fail-closed
    with pytest.raises(RetiredSourceError):
        at.link("c-2", "s-1", 7)
    # re-declaring a retired id is refused
    with pytest.raises(RetiredSourceError):
        at.source("s-1", "third-party", 8)
    # retiring twice is refused
    with pytest.raises(RetiredSourceError):
        at.retire("s-1", 9)


def test_12_seq_discipline():
    at = Attribution()
    at.source("s-1", "ai-model", 1)
    # rewind raises bare: no consumption, no rejected row
    with pytest.raises(SeqOrderError):
        at.source("s-2", "ai-model", 1)
    with pytest.raises(SeqOrderError):
        at.source("s-2", "ai-model", 0)
    # bare rewinds consume nothing and book no rejected rows; only the one
    # successful source-declared row is present
    log = at.audit_log(2)
    assert len(log) == 1 and log[0]["kind"] == "source-declared"
    assert at.stats(3)["seq"] == 1
    # malformed seqs refused
    for bad in (True, "1", 1.0, None, -2):
        with pytest.raises(SeqOrderError):
            at.source("s-x", "ai-model", bad)
    assert at.stats(4)["seq"] == 1


def test_13_audit_shapes_leak_ban_and_bad_kind():
    at = Attribution()
    at.source("s-1", "automated-pipeline", 1)
    at.link("c-1", "s-1", 2, method="metadata", confidence=0.5)
    at.retire("s-1", 3, reason="manual")
    log = at.audit_log(4)
    assert [e["kind"] for e in log] == ["source-declared", "linked", "retired"]
    for e in log:
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "attribution"
        assert e["digest"].startswith("sha256:")
        banned = ("text", "content", "source", "payload", "raw", "body", "value",
                  "message", "justification", "explanation", "summary",
                  "description", "transcript", "prompt", "response")
        for key in e["detail"]:
            assert key not in banned, f"leaked {key}"
    # bad kind refused
    with pytest.raises(AuditKindError):
        attribution_audit_event("bogus-kind", 5)
    # banned detail keys refused
    for key in ("text", "payload", "source", "value"):
        with pytest.raises(AuditKindError):
            attribution_audit_event("linked", 6, **{key: "x"})
    # bad seq in builder
    with pytest.raises(SeqOrderError):
        attribution_audit_event("linked", True)


def test_14_digest_determinism_and_frozen_records():
    import dataclasses

    at1 = Attribution()
    at1.source("s-1", "data-corpus", 1)
    link1 = at1.link("c-1", "s-1", 2, method="provenance-graph", confidence=0.25)
    at2 = Attribution()
    at2.source("s-1", "data-corpus", 1)
    link2 = at2.link("c-1", "s-1", 2, method="provenance-graph", confidence=0.25)
    assert link1.digest == link2.digest
    assert at1.verify("c-1", 3).digest == at2.verify("c-1", 3).digest
    # records are frozen
    with pytest.raises(dataclasses.FrozenInstanceError):
        link1.content_id = "x"  # type: ignore
    # confidence 1 vs 1.0 pins identically
    assert at1.link_record("c-1", 4).confidence == link2.confidence


def test_15_main_subprocess():
    r = subprocess.run(
        [sys.executable, str(COMP / "attribution.py")],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, r.stderr
    assert "attribution OK: source, link, verify, retire, refusals" in r.stdout
