"""Provenance tagging tests."""

import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


pt = _load("provenance_tagging")


def test_tag_user():
    v = pt.tag_user("hello")
    assert v.provenance == "user"
    assert "user" in v.deps
    assert v.value == "hello"


def test_tag_tool_output():
    v = pt.tag_tool_output("data", "my_tool")
    assert v.provenance == "my_tool"
    assert "my_tool" in v.deps


def test_tag_tool_requires_id():
    with pytest.raises(pt.ProvenanceError):
        pt.tag_tool_output("data", "")


def test_combine_unions_provenance():
    a = pt.tag_user("a")
    b = pt.tag_tool_output("b", "tool1")
    c = pt.combine(a, b)
    assert "user" in c.deps
    assert "tool1" in c.deps
    assert c.value == ("a", "b")


def test_combine_intersects_readers():
    a = pt.TaggedValue(value="a", readers=frozenset({"alice", "bob"}))
    b = pt.TaggedValue(value="b", readers=frozenset({"bob", "carol"}))
    c = pt.combine(a, b)
    assert c.readers == frozenset({"bob"})


def test_policy_allows_trusted():
    policy = {"send": {"allowed_sources": {"user", "internal"}}}
    v = pt.tag_user("data")
    assert pt.check_policy("send", {"x": v}, policy) is True


def test_policy_denies_tainted():
    policy = {"send": {"allowed_sources": {"user", "internal"}}}
    v = pt.tag_tool_output("data", "evil_tool")
    assert pt.check_policy("send", {"x": v}, policy) is False


def test_policy_denies_untagged():
    policy = {"send": {"allowed_sources": {"user"}}}
    assert pt.check_policy("send", {"x": "raw_string"}, policy) is False  # type: ignore


def test_policy_denies_unknown_tool():
    policy = {"send": {"allowed_sources": {"user"}}}
    v = pt.tag_user("data")
    assert pt.check_policy("unknown_tool", {"x": v}, policy) is False


def test_transitive_closure():
    # A -> B -> C: C's deps include A's provenance.
    a = pt.tag_tool_output("a", "tool_a")
    b = pt.combine(a, pt.tag_user("b"))
    c = pt.combine(b, pt.tag_user("c"))
    assert "tool_a" in c.deps
    policy = {"send": {"allowed_sources": {"user", "internal"}}}
    assert pt.check_policy("send", {"x": c}, policy) is False


def test_stdlib_only():
    assert pt.stdlib_only() is True


def test_version_pin():
    assert pt.PROVENANCE_VERSION == "provenance-tagging.v1"
