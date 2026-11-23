"""Tests for content_authenticity.py — signature bookkeeping ledger."""

import ast
import dataclasses
import subprocess
import sys
from pathlib import Path

import pytest

import content_authenticity
from content_authenticity import (
    AUDIT_KINDS,
    REASONS,
    SCHEMA,
    VERSION,
    VERDICTS,
    AlreadyRevokedError,
    AuditKindError,
    BadDigestError,
    BadIdError,
    BadReasonError,
    ContentAuthenticity,
    ContentAuthenticityError,
    DuplicateIssuerError,
    SeqOrderError,
    UnknownContentError,
    UnknownIssuerError,
    UnknownSignatureError,
    content_authenticity_audit_event,
)

COMP = Path(__file__).resolve().parent.parent


def _pin(text: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_01_version_and_schema_pins():
    assert content_authenticity.VERSION == "content-authenticity.v1"
    assert content_authenticity.SCHEMA == "northstar.content-authenticity.v1"
    assert VERSION == "content-authenticity.v1"
    assert SCHEMA == "northstar.content-authenticity.v1"
    assert "content-authenticity.rejected" in AUDIT_KINDS
    assert set(VERDICTS) == {"authentic", "mismatch", "revoked", "unsigned"}
    assert "manual" in REASONS and "key-compromised" in REASONS


def test_02_stdlib_only_ast_check():
    src = (COMP / "content_authenticity.py").read_text()
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


def test_03_register_issuer_roundtrip_and_verify():
    ca = ContentAuthenticity()
    key_pin = _pin("public-key-bytes")
    rec = ca.register_issuer("newsroom", 1, key_digest=key_pin)
    assert rec.issuer_id == "newsroom"
    assert rec.key_digest == key_pin
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    d = rec.as_dict()
    assert d["schema"] == SCHEMA and d["version"] == VERSION
    assert ca.issuer_record("newsroom", 2) == rec
    assert ca.issuer_ids(3) == ("newsroom",)
    log = ca.audit_log(4)
    assert len(log) == 1 and log[0]["kind"] == "issuer-registered"
    # no key pin: allowed
    rec2 = ca.register_issuer("anon", 5)
    assert rec2.key_digest == "" and rec2.verify() is True


def test_04_register_issuer_bad_inputs_seq_burn_and_rejected_rows():
    ca = ContentAuthenticity()
    ca.register_issuer("ok", 1, key_digest=_pin("k"))
    bad = [
        ("ok", _pin("k")),  # duplicate
        ("", _pin("k")),  # empty id
        ("x" * 129, _pin("k")),  # too long
        (123, _pin("k")),  # non-str id
        (True, _pin("k")),  # bool id
        ("new-id", "raw-key"),  # bad digest pin
        ("new-id", 42),  # non-str digest
    ]
    seq = 1
    for iid, key in bad:
        seq += 1
        with pytest.raises(ContentAuthenticityError):
            ca.register_issuer(iid, seq, key_digest=key)
    log = ca.audit_log(seq + 1)
    rejected = [e for e in log if e["kind"] == "content-authenticity.rejected"]
    assert len(rejected) == len(bad)
    assert ca.stats(seq + 1)["issuers"] == 1


def test_05_sign_roundtrip_minted_ids_and_verify():
    ca = ContentAuthenticity()
    ca.register_issuer("newsroom", 1)
    pin = _pin("article body")
    sig = ca.sign("article-1", pin, "newsroom", 2)
    assert sig.signature_id == "sig-1"
    assert sig.content_id == "article-1"
    assert sig.content_digest == pin
    assert sig.issuer_id == "newsroom"
    assert sig.verify() is True
    sig2 = ca.sign("article-1", pin, "newsroom", 3)
    assert sig2.signature_id == "sig-2"
    assert [s.signature_id for s in ca.signatures_for("article-1", 4)] == [
        "sig-1",
        "sig-2",
    ]
    log = ca.audit_log(4)
    assert log[-1]["kind"] == "content-signed"


def test_06_sign_bad_inputs_and_unknown_issuer():
    ca = ContentAuthenticity()
    ca.register_issuer("newsroom", 1)
    pin = _pin("body")
    seq = 1
    bad = [
        ("a", "raw-not-a-pin", "newsroom"),  # raw content refused
        ("a", pin, "ghost-issuer"),  # unknown issuer
        ("", pin, "newsroom"),  # empty content id
        ("a", pin, ""),  # empty issuer id
        ("a", _pin("x")[:-1] + "z", "newsroom"),  # malformed pin
        ("a", pin, "newsroom",),  # ok shape but unknown -> still counted below
    ]
    n_fail = 0
    for args in bad[:5]:
        seq += 1
        with pytest.raises(ContentAuthenticityError):
            ca.sign(*args, seq)
        n_fail += 1
    # duplicate content re-sign is allowed (append ledger), only one sig per call
    log = ca.audit_log(seq + 1)
    rejected = [e for e in log if e["kind"] == "content-authenticity.rejected"]
    assert len(rejected) == n_fail
    assert ca.stats(seq + 1)["signatures"] == 0


def test_07_verify_authentic_is_pure_read():
    ca = ContentAuthenticity()
    ca.register_issuer("newsroom", 1)
    pin = _pin("article body")
    ca.sign("article-1", pin, "newsroom", 2)
    log_before = len(ca.audit_log(3))
    r1 = ca.verify("article-1", pin, 3)
    r2 = ca.verify("article-1", pin, 3)  # same seq reusable: pure read
    assert r1 == r2
    assert r1.verdict == "authentic"
    assert r1.matched_signature_id == "sig-1"
    assert r1.verify() is True
    d = r1.as_dict()
    assert d["schema"] == SCHEMA and d["version"] == VERSION
    assert len(ca.audit_log(3)) == log_before  # no audit row for reads


def test_08_verify_mismatch_and_unsigned_are_data():
    ca = ContentAuthenticity()
    ca.register_issuer("newsroom", 1)
    ca.sign("article-1", _pin("original"), "newsroom", 2)
    r = ca.verify("article-1", _pin("tampered"), 3)
    assert r.verdict == "mismatch" and r.matched_signature_id == "sig-1"
    r2 = ca.verify("never-signed", _pin("x"), 4)
    assert r2.verdict == "unsigned" and r2.matched_signature_id == ""
    # malformed view inputs refuse without consuming seq
    with pytest.raises(BadDigestError):
        ca.verify("article-1", "raw", 5)
    assert ca.stats(6)["seq"] == 2


def test_09_revoke_roundtrip_and_verify_after_revoke():
    ca = ContentAuthenticity()
    ca.register_issuer("newsroom", 1)
    pin = _pin("article body")
    ca.sign("article-1", pin, "newsroom", 2)
    rev = ca.revoke("sig-1", 3, reason="key-compromised")
    assert rev.signature_id == "sig-1"
    assert rev.reason == "key-compromised"
    assert rev.verify() is True
    assert ca.revocation_record("sig-1", 4) == rev
    assert ca.revoked_ids(4) == ("sig-1",)
    r = ca.verify("article-1", pin, 4)
    assert r.verdict == "revoked"
    log = ca.audit_log(4)
    assert log[-1]["kind"] == "signature-revoked"


def test_10_revoke_bad_inputs_and_double_revoke():
    ca = ContentAuthenticity()
    ca.register_issuer("newsroom", 1)
    ca.sign("article-1", _pin("b"), "newsroom", 2)
    ca.revoke("sig-1", 3)
    seq = 3
    bad = [
        ("sig-1", 4, "manual"),  # already revoked
        ("sig-9", 5, "manual"),  # unknown signature
        ("sig-1", 6, "not-a-reason"),  # bad reason
        ("sig-1", 7, True),  # bool reason
    ]
    errs = [AlreadyRevokedError, UnknownSignatureError, BadReasonError, BadReasonError]
    for (sid, s, reason), err in zip(bad, errs):
        with pytest.raises(err):
            ca.revoke(sid, s, reason=reason)
    assert ca.revoked_ids(8) == ("sig-1",)


def test_11_view_bad_inputs_and_stats():
    ca = ContentAuthenticity()
    ca.register_issuer("newsroom", 1)
    ca.sign("a", _pin("b"), "newsroom", 2)
    with pytest.raises(UnknownIssuerError):
        ca.issuer_record("ghost", 3)
    with pytest.raises(UnknownSignatureError):
        ca.signature_record("sig-9", 3)
    with pytest.raises(UnknownContentError):
        ca.signatures_for("nope", 3)
    with pytest.raises(UnknownSignatureError):
        ca.revocation_record("sig-1", 3)
    st = ca.stats(3)
    assert st == {"issuers": 1, "signatures": 1, "revocations": 0, "contents": 1, "seq": 2}


def test_12_seq_discipline_rewind_bare_and_malformed():
    ca = ContentAuthenticity()
    with pytest.raises(SeqOrderError):
        ca.register_issuer("x", 0)  # not > initial 0? 0 not strictly greater
    ca.register_issuer("x", 1)
    with pytest.raises(SeqOrderError):
        ca.register_issuer("y", 1)  # rewind: raises bare, consumes nothing
    assert ca.stats(2)["seq"] == 1
    assert len(ca.audit_log(2)) == 1  # no rejected row for the bare rewind
    for bad in (True, "2", 2.0, None, -1):
        with pytest.raises(SeqOrderError):
            ca.sign("c", _pin("d"), "x", bad)
    assert ca.stats(2)["seq"] == 1


def test_13_audit_shapes_leak_ban_and_bad_kind():
    ca = ContentAuthenticity()
    ca.register_issuer("newsroom", 1, key_digest=_pin("pubkey"))
    log = ca.audit_log(2)
    assert log[0]["schema"] == "audit.ndjson/1"
    assert log[0]["module"] == "content-authenticity"
    assert log[0]["detail"] == {"issuer_id": "newsroom"}
    for banned in ("content", "key", "public_key", "private_key", "reason", "value"):
        with pytest.raises(AuditKindError):
            content_authenticity_audit_event(
                "content-signed", 3, **{banned: "x"}
            )
    with pytest.raises(AuditKindError):
        content_authenticity_audit_event("bogus-kind", 3)


def test_14_cross_instance_digest_determinism_and_tamper():
    def build():
        ca = ContentAuthenticity()
        ca.register_issuer("newsroom", 1, key_digest=_pin("pubkey"))
        return ca.sign("a", _pin("body"), "newsroom", 2)

    s1, s2 = build(), build()
    assert s1 == s2 and s1.digest == s2.digest
    tampered = dataclasses.replace(s1, issuer_id="hacker")
    assert tampered.verify() is False
    ca = ContentAuthenticity()
    ca.register_issuer("newsroom", 1)
    ca.sign("a", _pin("body"), "newsroom", 2)
    r1, r2 = ca.verify("a", _pin("body"), 3), ca.verify("a", _pin("body"), 3)
    assert r1 == r2 and r1.digest == r2.digest


def test_15_main_subprocess_check():
    result = subprocess.run(
        [sys.executable, str(COMP / "content_authenticity.py")],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "content-authenticity OK" in result.stdout
