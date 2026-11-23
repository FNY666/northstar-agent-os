"""Tests for agent_memory: key-addressed memory slot ledger."""

import ast
import subprocess
import sys

import pytest

import agent_memory as am
from agent_memory import AgentMemory


def _module_path():
    return am.__file__


# ---------------------------------------------------------------------------
# pins & stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert am.AGENT_MEMORY_VERSION == "agent-memory.v1"
    assert am.AGENT_MEMORY_SCHEMA == "northstar.agent-memory.v1"
    assert am.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(open(_module_path(), encoding="utf-8").read())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing",
        "__future__", "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------


def test_store_roundtrip_and_digest():
    m = AgentMemory()
    rec = m.store("pref/theme", "dark", 1, tags=("pref", "ui"))
    assert rec.key == "pref/theme"
    assert rec.content == "dark"
    assert rec.tags == ("pref", "ui")  # sorted
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify("pref/theme", "dark", ("pref", "ui"))
    assert not rec.verify("pref/theme", "light", ("pref", "ui"))
    assert not rec.verify("other", "dark", ("pref", "ui"))
    assert m.memory_record("pref/theme") == rec
    assert m.memory_record("nope") is None
    assert m.keys() == ("pref/theme",)


def test_store_duplicate_and_bad_keys_consume_seq_and_audit_rejected():
    m = AgentMemory()
    m.store("k1", "v", 1)
    with pytest.raises(am.DuplicateKeyError):
        m.store("k1", "v2", 2)
    with pytest.raises(am.BadKeyError):
        m.store("", "v", 3)
    with pytest.raises(am.BadKeyError):
        m.store("has space", "v", 4)
    with pytest.raises(am.BadKeyError):
        m.store("x" * 257, "v", 5)
    with pytest.raises(am.BadKeyError):
        m.store(123, "v", 6)
    with pytest.raises(am.BadKeyError):
        m.store(True, "v", 7)
    rejected = [r for r in m.audit_log() if r["kind"] == "rejected"]
    assert len(rejected) == 6
    assert [r["seq"] for r in rejected] == [2, 3, 4, 5, 6, 7]
    assert m.keys() == ("k1",)


def test_store_bad_content_and_bad_tags():
    m = AgentMemory()
    bad_contents = ["", None, 123, True, b"bytes", "x" * 65_537]
    seq = 1
    for content in bad_contents:
        with pytest.raises(am.BadContentError):
            m.store(f"k{seq}", content, seq)
        seq += 1
    assert len([r for r in m.audit_log()
                if r["kind"] == "rejected"]) == len(bad_contents)
    bad_tags = ["str-not-list", ("",), ("has space",), ("x" * 65,),
                (123,), (True,), tuple(f"t{i}" for i in range(33))]
    for tags in bad_tags:
        with pytest.raises(am.BadTagError):
            m.store(f"k{seq}", "v", seq, tags=tags)
        seq += 1
    # Duplicate tags dedupe deterministically instead of raising.
    rec = m.store("dedup", "v", seq, tags=("b", "a", "b"))
    assert rec.tags == ("a", "b")
    assert m.keys() == ("dedup",)


# ---------------------------------------------------------------------------
# recall / search (pure reads)
# ---------------------------------------------------------------------------


def test_recall_found_and_unknown_as_data():
    m = AgentMemory()
    m.store("pref/theme", "dark", 1, tags=("pref",))
    rep = m.recall("pref/theme", 1)
    assert rep.found is True
    assert rep.record is not None
    assert rep.record.content == "dark"
    assert rep.record.key == "pref/theme"
    unknown = m.recall("nope", 1)
    assert unknown.found is False
    assert unknown.record is None
    assert unknown.key == "nope"


def test_recall_and_search_are_pure_reads():
    m = AgentMemory()
    m.store("a", "1", 1, tags=("t",))
    m.store("b", "2", 2, tags=("t", "u"))
    n_before = len(m.audit_log())
    # Same seq reused on reads: no consumption, no audit rows.
    m.recall("a", 2)
    m.recall("a", 2)
    m.search(("t",), 2)
    assert len(m.audit_log()) == n_before
    # Read of a retired key is also data, not an error.
    m.forget("a", 3)
    assert m.recall("a", 3).found is False
    with pytest.raises(am.BadKeyError):
        m.recall("", 4)
    with pytest.raises(am.SeqOrderError):
        m.recall("a", "bad-seq")


def test_search_tag_matching_limit_and_no_match():
    m = AgentMemory()
    m.store("a", "1", 1, tags=("red",))
    m.store("b", "2", 2, tags=("red", "blue"))
    m.store("c", "3", 3, tags=("green",))
    assert m.search(("red",), 3).keys == ("a", "b")
    assert m.search(("red", "blue"), 3).keys == ("b",)
    assert m.search(("zzz",), 3).keys == ()
    assert m.search((), 3).keys == ("a", "b", "c")
    assert m.search(("red",), 3, limit=1).keys == ("a",)
    with pytest.raises(am.BadLimitError):
        m.search(("red",), 3, limit=0)
    with pytest.raises(am.BadLimitError):
        m.search(("red",), 3, limit=True)
    # Forgotten keys drop out of search results.
    m.forget("b", 4)
    assert m.search(("red",), 4).keys == ("a",)


# ---------------------------------------------------------------------------
# forget
# ---------------------------------------------------------------------------


def test_forget_lifecycle_and_terminality():
    m = AgentMemory()
    m.store("old/creds", "secret", 1, tags=("sensitive",))
    fr = m.forget("old/creds", 2, reason="expired")
    assert fr.key == "old/creds"
    assert fr.reason == "expired"
    assert fr.seq == 2
    assert fr.digest.startswith("sha256:")
    assert fr.verify("old/creds", "expired")
    assert not fr.verify("old/creds", "manual")
    assert m.keys() == ()
    assert m.retired_keys() == ("old/creds",)
    # Terminal: re-store and re-forget both refused; unknown refused.
    with pytest.raises(am.RetiredKeyError):
        m.store("old/creds", "again", 3)
    with pytest.raises(am.RetiredKeyError):
        m.forget("old/creds", 4)
    with pytest.raises(am.UnknownKeyError):
        m.forget("never-existed", 5)
    with pytest.raises(am.BadReasonError):
        m.forget("x", 6, reason="y" * 257)
    rejected = [r for r in m.audit_log() if r["kind"] == "rejected"]
    assert len(rejected) == 4
    stats = m.stats(6)
    assert stats == {"live": 0, "retired": 1, "audit_rows": 6}, stats


# ---------------------------------------------------------------------------
# seq discipline
# ---------------------------------------------------------------------------


def test_seq_ordering_rewind_bare_and_malformed():
    m = AgentMemory()
    m.store("k", "v", 1)
    # Rewind raises bare, consumes nothing: next valid seq still works.
    with pytest.raises(am.SeqOrderError):
        m.store("k2", "v", 1)
    rec = m.store("k2", "v", 2)
    assert rec.key == "k2"
    assert len([r for r in m.audit_log()
                if r["kind"] == "rejected"]) == 0
    for bad in (True, -1, 1.5, "2", None):
        with pytest.raises(am.SeqOrderError):
            m.store("k3", "v", bad)
    # Reads validate shape only.
    m.recall("k", 2)
    m.search((), 2)
    m.stats(2)


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    m = AgentMemory()
    m.store("k1", "secret-content", 1, tags=("sensitive",))
    m.forget("k1", 2, reason="manual")
    rows = m.audit_log()
    assert [r["kind"] for r in rows] == ["memory-stored", "memory-forgotten"]
    stored = rows[0]
    assert stored["schema"] == "audit.ndjson/1"
    assert stored["module"] == "agent-memory.v1"
    assert stored["seq"] == 1
    assert stored["detail"]["key"] == "k1"
    assert stored["detail"]["digest"].startswith("sha256:")
    blob = str(rows).lower()
    assert "secret-content" not in blob
    assert "sensitive" not in blob
    # Banned keys rejected at the builder.
    for banned in ("content", "tags", "payload", "raw", "value", "data"):
        with pytest.raises(am.AuditKindError):
            am.agent_memory_audit_event("memory-stored",
                                        {"key": "k", banned: "x"}, 3)
    with pytest.raises(am.AuditKindError):
        am.agent_memory_audit_event("bogus-kind", {"key": "k"}, 3)
    # Rejected-row shape.
    m2 = AgentMemory()
    with pytest.raises(am.DuplicateKeyError):
        m2.store("k", "v", 1)
        m2.store("k", "v", 2)
    row = m2.audit_log()[-1]
    assert row["kind"] == "rejected"
    assert row["detail"]["error"] == "DuplicateKeyError"


# ---------------------------------------------------------------------------
# cross-instance & main
# ---------------------------------------------------------------------------


def test_concurrency_smoke():
    import threading
    m = AgentMemory()
    errors = []

    def work(i):
        try:
            m.store(f"ck-{i}", f"v-{i}", i + 1, tags=(f"t{i % 3}",))
            m.recall(f"ck-{i}", i + 1)
        except Exception as e:  # pragma: no cover - must not happen
            errors.append(e)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    # Sequential seqs, so join order does not matter for strict increase.
    # Run sequentially-by-join to keep seq claims ordered.
    for t in threads:
        t.start()
        t.join()
    assert not errors
    assert len(m.keys()) == 8
    assert m.search(("t0",), 9).keys == ("ck-0", "ck-3", "ck-6")


def test_cross_instance_digest_determinism():
    a, b = AgentMemory(), AgentMemory()
    ra = a.store("k", "v", 1, tags=("t1", "t2"))
    rb = b.store("k", "v", 1, tags=("t2", "t1"))  # order-independent
    assert ra.digest == rb.digest
    fa = a.forget("k", 2, reason="manual")
    fb = b.forget("k", 2, reason="manual")
    assert fa.digest == fb.digest


def test_frozen_records_and_views():
    m = AgentMemory()
    rec = m.store("k", "v", 1, tags=("t",))
    with pytest.raises(Exception):
        rec.key = "other"  # frozen
    with pytest.raises(Exception):
        rec.content = "other"  # frozen
    fr = m.forget("k", 2)
    with pytest.raises(Exception):
        fr.reason = "other"  # frozen
    assert m.keys() == ()
    assert m.retired_keys() == ("k",)
    stats = m.stats(2)
    assert stats["live"] == 0 and stats["retired"] == 1


def test_main_subprocess():
    r = subprocess.run([sys.executable, _module_path()],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == \
        "agent-memory OK: store, recall, search, forget, terminal"
