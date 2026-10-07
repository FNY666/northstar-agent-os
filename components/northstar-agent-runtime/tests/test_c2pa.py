"""Tests for c2pa: C2PA manifest/assertion decision ledger (simulated)."""

import ast
import subprocess
import sys

import pytest

import c2pa as c2
from c2pa import C2PA

_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64


def _module_path():
    return c2.__file__


# ---------------------------------------------------------------------------
# pins & stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert c2.C2PA_VERSION == "c2pa.v1"
    assert c2.C2PA_SCHEMA == "northstar.c2pa.v1"
    assert c2.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(open(_module_path(), encoding="utf-8").read())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "__future__",
        "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------


def test_manifest_roundtrip_and_digest():
    c = C2PA()
    rec = c.manifest("man-001", _DIGEST_A, 1, generator="gen-1")
    assert rec.manifest_id == "man-001"
    assert rec.asset_digest == _DIGEST_A
    assert rec.generator == "gen-1"
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify(_DIGEST_A, "gen-1")
    assert not rec.verify(_DIGEST_B, "gen-1")
    assert c.manifest_record("man-001") == rec
    assert c.manifest_record("nope") is None
    assert c.manifest_ids() == ("man-001",)


def test_manifest_duplicate_and_bad_inputs_consume_seq_and_audit_rejected():
    c = C2PA()
    c.manifest("m1", _DIGEST_A, 1)
    with pytest.raises(c2.DuplicateManifestError):
        c.manifest("m1", _DIGEST_A, 2)
    with pytest.raises(c2.BadManifestError):
        c.manifest("", _DIGEST_A, 3)
    with pytest.raises(c2.BadManifestError):
        c.manifest("has space", _DIGEST_A, 4)
    with pytest.raises(c2.BadManifestError):
        c.manifest("x" * 257, _DIGEST_A, 5)
    with pytest.raises(c2.BadAssetError):
        c.manifest("m2", "not-a-digest", 6)
    with pytest.raises(c2.BadAssetError):
        c.manifest("m2", "sha256:", 7)
    with pytest.raises(c2.SeqOrderError):
        c.manifest("m3", _DIGEST_A, 7)  # rewind: bare
    kinds = [r["kind"] for r in c.audit_log()]
    assert kinds.count("rejected") == 6
    assert len(c.audit_log()) == 1 + 6


# ---------------------------------------------------------------------------
# assertion
# ---------------------------------------------------------------------------


def test_assertion_roundtrip_and_digest():
    c = C2PA()
    c.manifest("man-001", _DIGEST_A, 1)
    rec = c.assertion("man-001", "a-001", "ingredient", 2,
                      content_digest=_DIGEST_B)
    assert rec.assertion_id == "a-001"
    assert rec.kind == "ingredient"
    assert rec.content_digest == _DIGEST_B
    assert rec.digest.startswith("sha256:")
    assert rec.verify("man-001", "ingredient", _DIGEST_B)
    assert not rec.verify("man-001", "action", _DIGEST_B)
    assert c.assertion_record("man-001", "a-001") == rec
    assert c.assertion_record("man-001", "nope") is None
    assert c.assertion_ids("man-001") == ("a-001",)
    # content pin is optional
    r2 = c.assertion("man-001", "a-002", "action", 3)
    assert r2.content_digest == ""
    assert r2.verify("man-001", "action", "")


def test_assertion_bad_inputs_and_unknown_manifest_consume_seq():
    c = C2PA()
    c.manifest("man-001", _DIGEST_A, 1)
    with pytest.raises(c2.UnknownManifestError):
        c.assertion("ghost", "a-1", "action", 2)
    with pytest.raises(c2.BadAssertionError):
        c.assertion("man-001", "", "action", 3)
    with pytest.raises(c2.BadKindError):
        c.assertion("man-001", "a-1", "not-a-kind", 4)
    with pytest.raises(c2.BadDigestError):
        c.assertion("man-001", "a-1", "action", 5,
                    content_digest="raw-content")
    c.assertion("man-001", "a-1", "action", 6, content_digest=_DIGEST_B)
    with pytest.raises(c2.DuplicateAssertionError):
        c.assertion("man-001", "a-1", "action", 7,
                    content_digest=_DIGEST_B)
    # same assertion id on a different manifest is fine
    c.manifest("man-002", _DIGEST_B, 8)
    ok = c.assertion("man-002", "a-1", "action", 9,
                     content_digest=_DIGEST_B)
    assert ok.verify("man-002", "action", _DIGEST_B)
    kinds = [r["kind"] for r in c.audit_log()]
    assert kinds.count("rejected") == 5
    assert c.assertion_ids("man-002") == ("a-1",)


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def test_verify_roundtrip_pure_read():
    c = C2PA()
    c.manifest("man-001", _DIGEST_A, 1)
    c.assertion("man-001", "a-001", "ingredient", 2,
                content_digest=_DIGEST_B)
    c.assertion("man-001", "a-002", "action", 3,
                content_digest=_DIGEST_B)
    rep = c.verify("man-001", 3)  # same seq as a mutation: pure read
    assert rep.pins_ok is True
    assert rep.has_assertions is True
    assert rep.all_pinned is True
    assert rep.assertion_count == 2
    assert rep.digest.startswith("sha256:")
    assert rep.verify(True, True, True, 2)
    assert not rep.verify(True, True, True, 3)
    # read consumes no seq, writes no audit row
    rep2 = c.verify("man-001", 2)
    assert rep2.digest != rep.digest  # seq is domain-separated
    c.assertion("man-001", "a-003", "action", 4,
                content_digest=_DIGEST_B)  # seq 4 still free
    kinds = [r["kind"] for r in c.audit_log()]
    assert "rejected" not in kinds


def test_verify_empty_manifest_and_unpinned():
    c = C2PA()
    c.manifest("bare", _DIGEST_A, 1)
    rep = c.verify("bare", 2)
    assert rep.pins_ok is True
    assert rep.has_assertions is False
    assert rep.all_pinned is True  # vacuous over zero assertions
    assert rep.assertion_count == 0
    c.assertion("bare", "u-1", "action", 3)  # no content pin
    rep2 = c.verify("bare", 4)
    assert rep2.all_pinned is False
    assert rep2.assertion_count == 1


def test_verify_unknown_manifest_refuses_without_consuming():
    c = C2PA()
    c.manifest("man-001", _DIGEST_A, 1)
    with pytest.raises(c2.UnknownManifestError):
        c.verify("ghost", 2)
    # unknown id raises before seq bookkeeping: seq 2 still free
    c.assertion("man-001", "a-1", "action", 2, content_digest=_DIGEST_B)
    assert c.assertion_ids("man-001") == ("a-1",)


def test_tampered_record_breaks_verify():
    c = C2PA()
    c.manifest("man-001", _DIGEST_A, 1)
    rec = c.assertion("man-001", "a-001", "ingredient", 2,
                      content_digest=_DIGEST_B)
    # forge the kind off-ledger: the booked pin no longer matches
    forged = c2.AssertionRecord(assertion_id=rec.assertion_id,
                                manifest_id=rec.manifest_id,
                                kind="action",
                                content_digest=rec.content_digest,
                                seq=rec.seq, digest=rec.digest)
    assert not forged.verify("man-001", "action", _DIGEST_B)
    assert rec.verify("man-001", "ingredient", _DIGEST_B)


# ---------------------------------------------------------------------------
# audit boundary
# ---------------------------------------------------------------------------


def test_audit_shapes_and_raw_bytes_never_cross():
    c = C2PA()
    c.manifest("man-001", _DIGEST_A, 1, generator="g")
    c.assertion("man-001", "a-001", "ingredient", 2,
                content_digest=_DIGEST_B)
    rows = c.audit_log()
    assert [r["kind"] for r in rows] == ["manifest-declared", "asserted"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "c2pa.v1"
        assert set(r.keys()) == {"schema", "module", "kind", "seq",
                                 "detail"}
    blob = repr(rows)
    # raw asset bytes / content never crossed: only digests do
    assert "fake-raw-asset-bytes" not in blob
    with pytest.raises(c2.AuditKindError):
        c2.c2pa_audit_event("bogus-kind", {}, 3)
    with pytest.raises(c2.AuditKindError):
        c2.c2pa_audit_event("asserted", {"content": "leak"}, 3)


# ---------------------------------------------------------------------------
# seq discipline
# ---------------------------------------------------------------------------


def test_seq_discipline_rewind_bare_and_malformed():
    c = C2PA()
    c.manifest("m1", _DIGEST_A, 1)
    with pytest.raises(c2.SeqOrderError):
        c.manifest("m2", _DIGEST_A, 1)  # rewind: bare, no consumption
    with pytest.raises(c2.SeqOrderError):
        c.manifest("m2", _DIGEST_A, True)
    with pytest.raises(c2.SeqOrderError):
        c.manifest("m2", _DIGEST_A, -1)
    with pytest.raises(c2.SeqOrderError):
        c.manifest("m2", _DIGEST_A, "2")
    # no rejected rows: rewinds and malformed seqs raise pre-claim
    assert c.audit_log() == tuple(r for r in c.audit_log()
                                  if r["kind"] == "manifest-declared")
    c.manifest("m2", _DIGEST_A, 2)  # seq 2 was never consumed
    assert c.manifest_ids() == ("m1", "m2")


# ---------------------------------------------------------------------------
# concurrency, main, standalone
# ---------------------------------------------------------------------------


def test_concurrent_pure_reads_stay_consistent():
    import threading
    c = C2PA()
    c.manifest("man-001", _DIGEST_A, 1)
    c.assertion("man-001", "a-001", "ingredient", 2,
                content_digest=_DIGEST_B)
    results = []
    def reader():
        for _ in range(50):
            rep = c.verify("man-001", 3)
            results.append(rep.digest)
    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 200
    assert len(set(results)) == 1


def test_cross_instance_determinism():
    def build():
        c = C2PA()
        c.manifest("man-001", _DIGEST_A, 1, generator="g")
        c.assertion("man-001", "a-001", "ingredient", 2,
                    content_digest=_DIGEST_B)
        return c.verify("man-001", 3).digest
    assert build() == build()


def test_main_subprocess():
    out = subprocess.run(
        [sys.executable, _module_path()],
        capture_output=True, text=True, cwd="/tmp")
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == \
        "c2pa OK: manifest, assertion, verify, pins, audit"
