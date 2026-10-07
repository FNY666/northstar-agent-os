"""Tests for tool_use: tool registration and invocation-booking ledger."""

import ast
import dataclasses
import json
import subprocess
import sys

import pytest

import tool_use as tu
from tool_use import ToolUse


def _module_path():
    return tu.__file__


def _schema(**overrides):
    base = {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer"},
            "verbose": {"type": "boolean"},
        },
        "required": ["query"],
        "description": "search the corpus",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# pins & stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert tu.TOOL_USE_VERSION == "tool-use.v1"
    assert tu.TOOL_USE_SCHEMA == "northstar.tool-use.v1"
    assert tu.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(open(_module_path(), encoding="utf-8").read())
    allowed = {
        "hashlib", "json", "math", "threading", "dataclasses", "typing",
        "__future__", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# register
# ---------------------------------------------------------------------------


def test_register_roundtrip_and_digest():
    t = ToolUse()
    rec = t.register("search", _schema(), 1)
    assert rec.tool_id == "search"
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.schema_digest.startswith("sha256:")
    assert rec.schema["required"] == ["query"]
    assert rec.verify("search", rec.schema)
    assert not rec.verify("search", _schema(description="other"))
    assert not rec.verify("other", rec.schema)
    assert t.tool_record("search") == rec
    assert t.tool_record("nope") is None
    assert t.tool_ids() == ("search",)
    # The stored schema is a copy: mutating the caller's dict changes nothing.
    s = _schema()
    t.register("copy", s, 2)
    s["properties"]["evil"] = {"type": "string"}
    assert "evil" not in t.tool_record("copy").schema["properties"]


def test_register_duplicate_and_bad_inputs_consume_seq():
    t = ToolUse()
    t.register("a", _schema(), 1)
    with pytest.raises(tu.DuplicateToolError):
        t.register("a", _schema(), 2)
    with pytest.raises(tu.BadSchemaError):
        t.register("b", ["not-a-dict"], 3)
    with pytest.raises(tu.BadSchemaError):
        t.register("b", {"type": "array"}, 4)
    with pytest.raises(tu.BadSchemaError):
        t.register("b", {"type": "object", "bogus": 1}, 5)
    with pytest.raises(tu.BadSchemaError):
        t.register("b", {"type": "object",
                          "properties": {"x": {"type": "weird"}}}, 6)
    with pytest.raises(tu.BadSchemaError):
        t.register("b", {"type": "object", "properties": {},
                          "required": ["missing"]}, 7)
    with pytest.raises(tu.BadSchemaError):
        t.register("b", {"type": "object",
                          "properties": {"x": {"type": "string",
                                               "bogus": 1}}}, 8)
    with pytest.raises(tu.BadToolError):
        t.register("", _schema(), 9)
    with pytest.raises(tu.BadToolError):
        t.register("has space", _schema(), 10)
    with pytest.raises(tu.BadToolError):
        t.register(True, _schema(), 11)
    # Failed mutations consumed their seqs: the next valid seq is 12.
    rec = t.register("b", _schema(), 12)
    assert rec.tool_id == "b"
    rejected = [r for r in t.audit_log() if r["kind"] == "rejected"]
    assert len(rejected) == 10
    assert all(r["detail"]["error"] for r in rejected)


# ---------------------------------------------------------------------------
# invoke
# ---------------------------------------------------------------------------


def test_invoke_roundtrip_and_digest():
    t = ToolUse()
    t.register("search", _schema(), 1)
    inv = t.invoke("search", {"query": "northstar", "limit": 5}, 2)
    assert inv.invocation_id == "invoke-1"
    assert inv.tool_id == "search"
    assert inv.arguments == {"query": "northstar", "limit": 5}
    assert inv.digest.startswith("sha256:")
    assert inv.verify("search", inv.arguments)
    assert not inv.verify("search", {"query": "other"})
    assert t.invocation("invoke-1") == inv
    assert t.invocation("invoke-9") is None
    assert t.invocation_ids() == ("invoke-1",)
    # Stored arguments are a copy.
    args = {"query": "x"}
    t.invoke("search", args, 3)
    args["injected"] = True
    assert "injected" not in t.invocation("invoke-2").arguments
    assert t.stats(3).invocations == 2
    assert t.stats(3).tools == 1


def test_invoke_unknown_tool_and_bad_args_consume_seq():
    t = ToolUse()
    t.register("search", _schema(), 1)
    with pytest.raises(tu.UnknownToolError):
        t.invoke("nope", {"query": "x"}, 2)
    with pytest.raises(tu.BadArgumentsError):
        t.invoke("search", {"limit": 5}, 3)  # missing required
    with pytest.raises(tu.BadArgumentsError):
        t.invoke("search", {"query": 123}, 4)  # wrong type
    with pytest.raises(tu.BadArgumentsError):
        t.invoke("search", {"query": "x", "bogus": 1}, 5)  # unknown key
    with pytest.raises(tu.BadArgumentsError):
        t.invoke("search", ["not-a-dict"], 6)
    with pytest.raises(tu.BadArgumentsError):
        t.invoke("search", {"query": "x", "limit": True}, 7)  # bool != int
    with pytest.raises(tu.BadArgumentsError):
        t.invoke("search", {"query": "x", "limit": 2 ** 54}, 8)  # unsafe int
    with pytest.raises(tu.BadToolError):
        t.invoke("", {"query": "x"}, 9)
    # Failed mutations consumed their seqs: next valid seq is 10.
    inv = t.invoke("search", {"query": "ok"}, 10)
    assert inv.invocation_id == "invoke-1"
    rejected = [r for r in t.audit_log() if r["kind"] == "rejected"]
    assert len(rejected) == 8


def test_type_vocabulary_roundtrip():
    t = ToolUse()
    schema = {
        "type": "object",
        "properties": {
            "s": {"type": "string"},
            "i": {"type": "integer"},
            "n": {"type": "number"},
            "b": {"type": "boolean"},
            "a": {"type": "array"},
            "o": {"type": "object"},
        },
    }
    t.register("typed", schema, 1)
    inv = t.invoke("typed", {
        "s": "text", "i": 7, "n": 2.5, "b": False,
        "a": [1, "two", {"three": 3}], "o": {"k": "v"},
    }, 2)
    assert inv.arguments["n"] == 2.5
    assert inv.verify("typed", inv.arguments)
    with pytest.raises(tu.BadArgumentsError):
        t.invoke("typed", {"s": "x" * 5000, "i": 0, "n": 0,
                           "b": True, "a": [], "o": {}}, 3)
    with pytest.raises(tu.BadArgumentsError):
        t.invoke("typed", {"s": "x", "i": float("nan"), "n": 0,
                           "b": True, "a": [], "o": {}}, 4)
    with pytest.raises(tu.BadArgumentsError):
        t.invoke("typed", {"s": "x", "i": 0, "n": 0, "b": True,
                           "a": [], "o": {1: "bad-key"}}, 5)


# ---------------------------------------------------------------------------
# schema view is a pure read
# ---------------------------------------------------------------------------


def test_schema_view_pure_read():
    t = ToolUse()
    t.register("search", _schema(), 1)
    v1 = t.schema("search", 2)
    v2 = t.schema("search", 2)  # same seq twice: nothing consumed
    assert v1 == v2
    assert v1.tool_id == "search"
    assert v1.seq == 2
    assert v1.schema_digest == t.tool_record("search").schema_digest
    kinds = [r["kind"] for r in t.audit_log()]
    assert kinds == ["tool-registered"]  # no audit rows for reads
    with pytest.raises(tu.UnknownToolError):
        t.schema("nope", 3)


# ---------------------------------------------------------------------------
# seq discipline
# ---------------------------------------------------------------------------


def test_seq_discipline():
    t = ToolUse()
    with pytest.raises(tu.SeqOrderError):
        t.register("a", _schema(), 0 - 1)
    with pytest.raises(tu.SeqOrderError):
        t.register("a", _schema(), True)
    with pytest.raises(tu.SeqOrderError):
        t.register("a", _schema(), "1")
    t.register("a", _schema(), 1)
    with pytest.raises(tu.SeqOrderError):
        t.register("a", _schema(), 1)  # rewind: bare, no consumption
    with pytest.raises(tu.SeqOrderError):
        t.register("b", _schema(), 1)  # still rewind, nothing burned
    assert [r["kind"] for r in t.audit_log()] == ["tool-registered"]
    t.register("b", _schema(), 2)
    assert t.tool_ids() == ("a", "b")


# ---------------------------------------------------------------------------
# views
# ---------------------------------------------------------------------------


def test_views():
    t = ToolUse()
    t.register("b-tool", _schema(), 1)
    t.register("a-tool", _schema(), 2)
    assert t.tool_ids() == ("a-tool", "b-tool")
    t.invoke("b-tool", {"query": "x"}, 3)
    t.invoke("a-tool", {"query": "y"}, 4)
    assert t.invocation_ids() == ("invoke-1", "invoke-2")
    stats = t.stats(4)
    assert stats.tools == 2 and stats.invocations == 2
    # Views are pure: reusing the same seq writes no audit rows.
    assert t.stats(4) == stats
    assert [r["kind"] for r in t.audit_log()] == [
        "tool-registered", "tool-registered", "invoked", "invoked"]


# ---------------------------------------------------------------------------
# audit boundary
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    t = ToolUse()
    t.register("search", _schema(), 1)
    t.invoke("search", {"query": "secret-query"}, 2)
    log = t.audit_log()
    assert len(log) == 2
    reg, inv = log
    assert reg["schema"] == "audit.ndjson/1"
    assert reg["module"] == "tool-use.v1"
    assert reg["kind"] == "tool-registered"
    assert reg["seq"] == 1
    assert reg["detail"] == {"tool_id": "search",
                             "schema_digest": t.tool_record("search").schema_digest,
                             "digest": t.tool_record("search").digest}
    assert inv["kind"] == "invoked"
    assert inv["detail"]["invocation_id"] == "invoke-1"
    assert inv["detail"]["tool_id"] == "search"
    # Raw arguments never appear in audit rows.
    assert "secret-query" not in json.dumps(log)
    # The builder bans raw keys and unknown kinds.
    with pytest.raises(tu.AuditKindError):
        tu.tool_use_audit_event("invoked", {"arguments": {}}, 3)
    with pytest.raises(tu.AuditKindError):
        tu.tool_use_audit_event("invoked", {"schema": {}}, 3)
    with pytest.raises(tu.AuditKindError):
        tu.tool_use_audit_event("bogus-kind", {}, 3)


def test_frozen_records():
    t = ToolUse()
    rec = t.register("search", _schema(), 1)
    inv = t.invoke("search", {"query": "x"}, 2)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.tool_id = "mutated"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        inv.arguments = {}  # type: ignore[misc]


def test_cross_instance_digest_determinism():
    def build():
        t = ToolUse()
        t.register("search", _schema(), 1)
        inv = t.invoke("search", {"query": "x", "limit": 3}, 2)
        return t.tool_record("search"), inv

    r1, i1 = build()
    r2, i2 = build()
    assert r1.digest == r2.digest
    assert i1.digest == i2.digest
    # Content changes the pin.
    t3 = ToolUse()
    r3 = t3.register("search", _schema(description="other"), 1)
    assert r3.digest != r1.digest


def test_schema_canonicalization_and_view_isolation():
    t = ToolUse()
    # Same schema, different key insertion order: same canonical pin.
    s1 = {"type": "object", "description": "d",
          "required": ["q"], "properties": {"q": {"type": "string"}}}
    s2 = {"properties": {"q": {"type": "string"}}, "required": ["q"],
          "description": "d", "type": "object"}
    t.register("s1", s1, 1)
    t.register("s2", s2, 2)
    # Canonical form identical despite key insertion order; the
    # schema_digest differs only because the pin is per-tool (tool_id).
    assert (tu.jcs_canonical_json(t.tool_record("s1").schema) ==
            tu.jcs_canonical_json(t.tool_record("s2").schema))
    assert (t.tool_record("s1").schema_digest !=
            t.tool_record("s2").schema_digest)
    # The view returns a copy: mutating it does not touch the ledger.
    view = t.schema("s1", 3)
    view.schema["properties"]["injected"] = {"type": "string"}
    assert "injected" not in t.tool_record("s1").schema["properties"]


def test_main_self_check():
    proc = subprocess.run([sys.executable, _module_path()],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "tool-use OK" in proc.stdout
