"""Tests for prompt_template: prompt template lifecycle ledger."""

import ast
import subprocess
import sys

import pytest

import prompt_template as ptm
from prompt_template import PromptTemplate


def _module_path():
    return ptm.__file__


# ---------------------------------------------------------------------------
# pins & stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert ptm.PROMPT_TEMPLATE_VERSION == "prompt-template.v1"
    assert ptm.PROMPT_TEMPLATE_SCHEMA == "northstar.prompt-template.v1"
    assert ptm.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(open(_module_path(), encoding="utf-8").read())
    allowed = {
        "hashlib", "re", "threading", "dataclasses", "typing",
        "__future__", "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# template registration
# ---------------------------------------------------------------------------


def test_template_roundtrip_and_digest():
    pt = PromptTemplate()
    rec = pt.template("greeting", "Hello, {{name}}! You are {{role}}.", 1)
    assert rec.template_id == "greeting"
    assert rec.variables == ("name", "role")
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify("Hello, {{name}}! You are {{role}}.", 1)
    assert not rec.verify("Hello, {{name}}! You are {{role}}.", 2)
    assert pt.template_record("greeting") == rec
    assert pt.template_record("nope") is None
    assert pt.template_ids() == ("greeting",)
    assert pt.version_count("greeting") == 1


def test_template_duplicate_and_bad_inputs_consume_seq_and_audit_rejected():
    pt = PromptTemplate()
    pt.template("t1", "Hi {{name}}.", 1)
    with pytest.raises(ptm.DuplicateTemplateError):
        pt.template("t1", "Hi {{name}}.", 2)
    bad_texts = [
        "",                       # empty
        "x" * 65537,              # too long
        "Hello {{name",           # unclosed
        "Hello {name}}",          # stray brace
        "Hello {{}}",             # empty placeholder
        "Hello {{9lives}}",       # bad name (leading digit)
        "Hello {{na me}}",        # bad name (space)
        "Hello {{n}}}",           # stray close
    ]
    seq = 3
    for text in bad_texts:
        with pytest.raises(ptm.BadTemplateError):
            pt.template("bad", text, seq)
        seq += 1
    for bad_id in ("", 123, None, "has space", "x" * 257):
        with pytest.raises(ptm.BadTemplateError):
            pt.template(bad_id, "Hi.", seq)
        seq += 1
    # Every failed mutation consumed its seq and booked a rejected row.
    rejected = [r for r in pt.audit_log()
                if r["kind"] == ptm.KIND_REJECTED]
    assert len(rejected) == 1 + len(bad_texts) + 5
    assert all(r["seq"] > 1 for r in rejected)


def test_distinct_from_template_engine_layer():
    # Flat {{var}} only: sibling template_engine owns sections/partials;
    # those mustaches are malformed here (fail-closed, distinct layer).
    pt = PromptTemplate()
    with pytest.raises(ptm.BadTemplateError):
        pt.template("sec", "{{#items}}x{{/items}}", 1)
    with pytest.raises(ptm.BadTemplateError):
        pt.template("part", "{{> footer}}", 2)


# ---------------------------------------------------------------------------
# versioning
# ---------------------------------------------------------------------------


def test_version_chain_links_prior_digest():
    pt = PromptTemplate()
    v1 = pt.template("p", "v1 {{a}}", 1)
    v2 = pt.version("p", "v2 {{a}} {{b}}", 2)
    v3 = pt.version("p", "v3 {{a}}", 3)
    assert v2.number == 2 and v3.number == 3
    assert v2.prior_digest == v1.digest
    assert v3.prior_digest == v2.digest
    assert v2.verify("v2 {{a}} {{b}}", v1.digest, 2)
    assert not v2.verify("v2 {{a}} {{b}}", v2.digest, 2)  # wrong prior
    assert pt.version_count("p") == 3
    assert pt.version_record("p", 1) == v1
    assert pt.version_record("p", 3) == v3
    assert pt.version_record("p", 4) is None
    assert pt.version_record("nope", 1) is None
    assert pt.declared_variables("p") == ("a",)  # latest version wins
    kinds = [r["kind"] for r in pt.audit_log()]
    assert kinds == [ptm.KIND_TEMPLATE_REGISTERED, ptm.KIND_VERSION_BOOKED,
                     ptm.KIND_VERSION_BOOKED]


def test_version_unknown_template_and_bad_text():
    pt = PromptTemplate()
    with pytest.raises(ptm.UnknownTemplateError):
        pt.version("ghost", "Hi {{a}}.", 1)
    pt.template("p", "Hi {{a}}.", 2)
    with pytest.raises(ptm.BadTemplateError):
        pt.version("p", "Broken {{a", 3)
    # Failed version still consumed its seq.
    assert pt.version_count("p") == 1


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------


def test_render_roundtrip_uses_latest_version():
    pt = PromptTemplate()
    pt.template("p", "Hello {{name}}.", 1)
    pt.version("p", "Hi {{name}}, {{title}}!", 2)
    rec = pt.render("p", {"name": "Ada", "title": "Dr"}, 3)
    assert rec.render_id == "render-1"
    assert rec.version == 2
    assert rec.rendered == "Hi Ada, Dr!"
    assert rec.variables == (("name", "Ada"), ("title", "Dr"))
    assert rec.verify("p", 2, (("name", "Ada"), ("title", "Dr")),
                      "Hi Ada, Dr!", 3)
    assert not rec.verify("p", 2, (("name", "Ada"), ("title", "Dr")),
                          "Hi Ada, Dr!", 4)
    assert pt.render_record("render-1") == rec
    assert pt.render_record("render-99") is None


def test_render_missing_and_unknown_variables_fail_closed():
    pt = PromptTemplate()
    pt.template("p", "{{a}} and {{b}}", 1)
    with pytest.raises(ptm.MissingVariableError):
        pt.render("p", {"a": "x"}, 2)
    with pytest.raises(ptm.UnknownVariableError):
        pt.render("p", {"a": "x", "b": "y", "c": "z"}, 3)
    with pytest.raises(ptm.UnknownTemplateError):
        pt.render("ghost", {}, 4)
    # Unlike the permissive template_engine, missing never renders empty.
    assert pt.render_record("render-1") is None


def test_render_bad_variable_values_and_escape_hatch():
    pt = PromptTemplate()
    pt.template("p", "{{n}}", 1)
    seq = 2
    for bad_vars in ({"n": 5}, {"n": None}, {"n": True}, {"n": ["x"]},
                     "not-a-dict", [("n", "x")], {1: "x"}):
        with pytest.raises(ptm.BadVariableError):
            pt.render("p", bad_vars, seq)
        seq += 1
    # Escape hatch: literal braces survive rendering.
    pt.template("lit", "Write \\{{n}} literally, and \\\\ backslash.", seq)
    rec = pt.render("lit", {}, seq + 1)
    assert rec.rendered == "Write {{n}} literally, and \\ backslash."


def test_render_cross_instance_digest_determinism():
    def build():
        pt = PromptTemplate()
        pt.template("p", "{{x}}+{{y}}", 1)
        return pt.render("p", {"x": "1", "y": "2"}, 2)
    a, b = build(), build()
    assert a.digest == b.digest
    assert a.rendered == "1+2"


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


def test_validate_verdict_as_data_and_report_verify():
    pt = PromptTemplate()
    ok = pt.validate("Dear {{title}} {{last}},", 1)
    assert ok.report_id == "report-1"
    assert ok.valid is True
    assert ok.problems == ()
    assert ok.text_digest.startswith("sha256:")
    assert ok.verify("Dear {{title}} {{last}},", 1)
    cases = {
        "Hello {{name": ptm.PROBLEM_UNBALANCED_BRACES,
        "Hello {name}}": ptm.PROBLEM_UNBALANCED_BRACES,
        "Hello {{}}": ptm.PROBLEM_EMPTY_PLACEHOLDER,
        "Hello {{9x}}": ptm.PROBLEM_BAD_VARIABLE_NAME,
        "x" * 65537: ptm.PROBLEM_TEXT_TOO_LONG,
    }
    seq = 2
    for text, problem in cases.items():
        rep = pt.validate(text, seq)
        assert rep.valid is False, text[:20]
        assert rep.problems == (problem,), text[:20]
        seq += 1
    # Validation never books a template; verdicts are data, never raised.
    assert pt.template_ids() == ()
    assert pt.validation_report("report-1") == ok
    with pytest.raises(ptm.BadTemplateError):
        pt.validate(123, seq)  # non-str input is fail-closed, not a verdict


# ---------------------------------------------------------------------------
# seq discipline, views, audit
# ---------------------------------------------------------------------------


def test_seq_ordering_rewind_bare_failed_mutation_burns():
    pt = PromptTemplate()
    pt.template("p", "{{a}}", 5)
    with pytest.raises(ptm.SeqOrderError):
        pt.template("q", "{{a}}", 5)   # rewind: bare, nothing consumed
    with pytest.raises(ptm.SeqOrderError):
        pt.template("q", "{{a}}", 3)   # rewind
    for bad in (True, "7", 7.0, -1, None):
        with pytest.raises(ptm.SeqOrderError):
            pt.validate("{{a}}", bad)
    # Failed mutation consumed its seq: next good seq must be > 5.
    with pytest.raises(ptm.DuplicateTemplateError):
        pt.template("p", "{{a}}", 6)
    pt.template("q", "{{a}}", 7)  # 6 was burned by the duplicate
    assert pt.template_ids() == ("p", "q")


def test_views_are_pure_reads_and_stats():
    pt = PromptTemplate()
    pt.template("p", "{{a}}", 1)
    pt.version("p", "{{a}}{{b}}", 2)
    pt.render("p", {"a": "x", "b": "y"}, 3)
    pt.validate("{{a}}", 4)
    before = len(pt.audit_log())
    # Same seq reused across pure views: nothing consumed, no audit rows.
    assert pt.declared_variables("p") == ("a", "b")
    assert pt.declared_variables("ghost") is None
    s = pt.stats(4)
    assert (s.templates, s.versions, s.renders, s.validations) == (1, 2, 1, 1)
    s2 = pt.stats(4)
    assert s == s2
    assert len(pt.audit_log()) == before
    # Frozen records cannot be mutated.
    rec = pt.template_record("p")
    with pytest.raises(Exception):
        rec.text = "tampered"  # type: ignore[misc]


def test_audit_shapes_and_leak_ban_and_bad_kind():
    pt = PromptTemplate()
    pt.template("p", "Hi {{name}}.", 1)
    pt.render("p", {"name": "Ada"}, 2)
    kinds = [r["kind"] for r in pt.audit_log()]
    assert kinds == [ptm.KIND_TEMPLATE_REGISTERED, ptm.KIND_RENDERED]
    for row in pt.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "prompt-template.v1"
        assert set(row["detail"]) == {
            "template_id", "variable_count", "digest"
        } or set(row["detail"]) == {
            "render_id", "template_id", "version", "digest"
        }
        # Raw text / rendered output / values never cross the boundary.
        assert "Hi {{name}}." not in str(row)
        assert "Ada" not in str(row)
    for banned in ("text", "rendered", "variables", "value", "payload", "raw"):
        with pytest.raises(ptm.AuditKindError):
            ptm.prompt_template_audit_event(ptm.KIND_RENDERED,
                                            {banned: "x"}, 3)
    with pytest.raises(ptm.AuditKindError):
        ptm.prompt_template_audit_event("nope", {}, 3)


def test_main_subprocess():
    proc = subprocess.run([sys.executable, _module_path()],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "prompt-template OK: register, version, render, validate, "
        "pins, audit")
