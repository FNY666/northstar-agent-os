"""Tests for developer_portal (15 tests)."""

import ast
import subprocess
import sys
import threading

import pytest

from developer_portal import (
    DeveloperPortal,
    developer_portal_audit_event,
    DocPage,
    TryRecord,
    ApiKey,
    KeyRevocation,
    DeveloperPortalError,
    BadDocError,
    BadTryError,
    DuplicateTryError,
    BadKeyError,
    DuplicateKeyError,
    UnknownKeyError,
    RevokedKeyError,
    AlreadyRevokedError,
    SeqOrderError,
    METHODS,
    _MODULE_VERSION,
    _SCHEMA_PIN,
)


def fresh():
    events = []
    return DeveloperPortal(audit=events.append), events


def test_version_pins():
    assert _MODULE_VERSION == "developer-portal.v1"
    assert _SCHEMA_PIN == "northstar.developer-portal.v1"


def test_stdlib_only():
    tree = ast.parse(open("developer_portal.py").read())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "__future__",
        "json", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_docs_roundtrip_and_versioning():
    dp, events = fresh()
    p = dp.docs("intro", "Intro", "# hi\n", 1, section="guides")
    assert isinstance(p, DocPage) and p.verify_digest()
    assert p.version == 1 and p.supersedes == "" and p.section == "guides"
    p2 = dp.docs("intro", "Intro", "# hi v2\n", 2)
    assert p2.verify_digest() and p2.version == 2 and p2.supersedes == p.digest
    assert p2.body_digest != p.body_digest
    assert dp.page("intro").version == 2
    assert dp.page_ids() == ["intro"]
    kinds = [e["event"] for e in events]
    assert kinds == ["docs-portal.page-published", "docs-portal.page-published"]


def test_docs_bad_inputs():
    dp, events = fresh()
    with pytest.raises(DeveloperPortalError):
        dp.docs("", "T", "b", 1)
    with pytest.raises(DeveloperPortalError):
        dp.docs("p", "", "b", 2)
    with pytest.raises(DeveloperPortalError):
        dp.docs("p", "T", "", 3)
    with pytest.raises(DeveloperPortalError):
        dp.docs("p", "T", "x" * ((1 << 20) + 1), 4)
    with pytest.raises(DeveloperPortalError):
        dp.page("missing")
    # failed mutations consumed their seqs and were audited
    assert [e["event"] for e in events].count("docs-portal.rejected") == 4
    assert dp.stats()["seq"] == 4


def test_try_roundtrip_and_refusals():
    dp, events = fresh()
    t = dp.try_it("t-1", "/v1/items", 1, method="POST", status=201,
                  body_digest="sha256:abc")
    assert isinstance(t, TryRecord) and t.verify_digest()
    assert t.status == 201 and t.method == "POST" and t.key_id == ""
    with pytest.raises(DuplicateTryError):
        dp.try_it("t-1", "/v1/items", 2)
    with pytest.raises(BadTryError):
        dp.try_it("t-2", "/v1/items", 3, method="FETCH")
    with pytest.raises(BadTryError):
        dp.try_it("t-2", "/v1/items", 4, status=99)
    with pytest.raises(BadTryError):
        dp.try_it("t-2", "", 5)
    assert dp.try_record("t-1").endpoint == "/v1/items"


def test_keys_roundtrip_and_revocation():
    dp, events = fresh()
    k = dp.keys("k-1", 1, label="ci", scopes=("read", "write"))
    assert isinstance(k, ApiKey) and k.verify_digest()
    assert k.scopes == ("read", "write") and not k.revoked
    assert k.key_ref.startswith("sha256:")
    with pytest.raises(DuplicateKeyError):
        dp.keys("k-1", 2)
    with pytest.raises(BadKeyError):
        dp.keys("k-2", 3, scopes="read")
    r = dp.revoke_key("k-1", 4, reason="rotation")
    assert isinstance(r, KeyRevocation) and r.verify_digest()
    assert dp.key("k-1").revoked
    with pytest.raises(AlreadyRevokedError):
        dp.revoke_key("k-1", 5)
    with pytest.raises(UnknownKeyError):
        dp.revoke_key("nope", 6)
    with pytest.raises(UnknownKeyError):
        dp.key("nope")
    assert dp.active_key_ids() == []
    assert dp.stats()["revoked_keys"] == 1


def test_try_with_revoked_and_unknown_key():
    dp, _ = fresh()
    dp.keys("k-1", 1)
    dp.revoke_key("k-1", 2)
    with pytest.raises(RevokedKeyError):
        dp.try_it("t-1", "/v1/x", 3, key_id="k-1")
    with pytest.raises(UnknownKeyError):
        dp.try_it("t-2", "/v1/x", 4, key_id="ghost")
    # active key works
    dp.keys("k-2", 5)
    t = dp.try_it("t-3", "/v1/x", 6, key_id="k-2")
    assert t.verify_digest() and t.key_id == "k-2"


def test_seq_ordering_and_consumption():
    dp, _ = fresh()
    with pytest.raises(SeqOrderError):
        dp.docs("p", "T", "b", 0)
    with pytest.raises(SeqOrderError):
        dp.docs("p", "T", "b", True)
    dp.docs("p", "T", "b", 1)
    with pytest.raises(SeqOrderError):
        dp.docs("p", "T", "b", 1)  # rewind
    # failed mutations consume their seq
    with pytest.raises(DeveloperPortalError):
        dp.docs("", "T", "b", 2)
    dp.docs("p2", "T", "b", 3)
    assert dp.stats()["seq"] == 3


def test_audit_shapes_and_bans():
    ev = developer_portal_audit_event(
        "docs-portal.page-published", {"page_id": "p", "version": 1}, 1
    )
    assert ev["module"] == _MODULE_VERSION and ev["seq"] == 1
    with pytest.raises(DeveloperPortalError):
        developer_portal_audit_event("nope.kind", {}, 1)
    with pytest.raises(DeveloperPortalError):
        developer_portal_audit_event(
            "docs-portal.page-published", {"body": "raw markdown"}, 1
        )
    with pytest.raises(DeveloperPortalError):
        developer_portal_audit_event(
            "docs-portal.key-issued", {"key_material": "hunter2"}, 1
        )
    with pytest.raises(DeveloperPortalError):
        developer_portal_audit_event("docs-portal.try-recorded", {}, 0)
    # key material never enters records either
    dp, _ = fresh()
    k = dp.keys("k-1", 1)
    assert "hunter2" not in repr(k)


def test_cross_instance_determinism():
    a = DeveloperPortal()
    b = DeveloperPortal()
    pa = a.docs("p", "T", "body", 1)
    pb = b.docs("p", "T", "body", 1)
    assert pa.digest == pb.digest
    ka = a.keys("k", 2, scopes=("read",))
    kb = b.keys("k", 2, scopes=("read",))
    assert ka.digest == kb.digest and ka.key_ref == kb.key_ref


def test_views_and_stats():
    dp, _ = fresh()
    dp.docs("p1", "T1", "b1", 1)
    dp.docs("p2", "T2", "b2", 2)
    dp.keys("k1", 3)
    dp.try_it("t1", "/v1/a", 4)
    s = dp.stats()
    assert s["pages"] == 2 and s["tries"] == 1 and s["keys"] == 1
    assert dp.key_ids() == ["k1"] and dp.active_key_ids() == ["k1"]
    d = dp.as_dict()
    assert set(d) == {"pages", "tries", "keys", "revocations", "seq"}
    assert d["pages"]["p1"]["title"] == "T1"


def test_concurrent_publishing():
    dp, _ = fresh()
    errs = []

    def worker(i):
        try:
            dp.docs(f"p-{i}", f"T{i}", f"body {i}", 1 + i)
        except Exception as exc:  # noqa: BLE001
            errs.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert not errs and len(dp.page_ids()) == 8


def test_methods_vocabulary():
    assert "GET" in METHODS and "POST" in METHODS
    assert "FETCH" not in METHODS


def test_try_keyword_is_reserved_so_method_is_try_it():
    # `def try(...)` is a SyntaxError in Python; the spec's `try()` ships as
    # `try_it` and the module docstring says so.
    import developer_portal as mod

    assert hasattr(DeveloperPortal, "try_it")
    assert not hasattr(DeveloperPortal, "try")
    assert "try`` is a" in mod.__doc__ or "reserved keyword" in mod.__doc__


def test_main_self_check():
    out = subprocess.run(
        [sys.executable, "developer_portal.py"],
        capture_output=True, text=True, cwd=".",
    )
    assert out.returncode == 0, out.stderr
    assert "developer-portal OK" in out.stdout
