"""15 tests for token_counter.py (P0 batch 44)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import token_counter as tc

HERE = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------- pins & stdlib

def test_version_and_schema_pins():
    assert tc.VERSION == "token-counter.v1"
    assert tc.SCHEMA == "northstar.token-counter.v1"
    assert tc.ESTIMATE_RULES == {"whitespace": 5, "char": 1, "wordpiece": 4}


def test_stdlib_only():
    src = (HERE / "token_counter.py").read_text()
    tree = ast.parse(src)
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "json",
               "threading", "typing", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed, node.module


# ---------------------------------------------------------------- register

def _ws(seq0=1):
    c = tc.TokenCounter()
    rec = c.register_tokenizer("tok", seq0)
    return c, rec


def test_register_roundtrip_and_verify():
    c, rec = _ws()
    assert rec.tokenizer_id == "tok"
    assert rec.kind == "whitespace"
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.token-counter.v1"
    assert c.tokenizer("tok").digest == rec.digest


def test_register_duplicate_and_bad_inputs_consume_seq_and_audit_rejected():
    c, _ = _ws()
    with pytest.raises(tc.DuplicateTokenizerError):
        c.register_tokenizer("tok", 2)
    for bad_seq, bad_id, bad_kind, bad_vs in [
            (3, "", "whitespace", 0),
            (4, "x" * 257, "whitespace", 0),
            (5, "a b", "whitespace", 0),
            (6, "t2", "bpe-x", 0),
            (7, "t3", "whitespace", -1),
            (8, "t4", "whitespace", True)]:
        with pytest.raises((tc.BadTokenizerError, tc.BadKindError)):
            c.register_tokenizer(bad_id, bad_seq, kind=bad_kind,
                                 vocab_size=bad_vs)
    # every failed mutation consumed its seq and booked a rejected row
    kinds = [r["kind"] for r in c.audit_log()]
    assert kinds.count("rejected") == 7
    assert c.stats()["last_seq"] == 8


def test_register_seq_rewind_raises_bare_without_consuming():
    c, _ = _ws()
    before = len(c.audit_log())
    with pytest.raises(tc.SeqOrderError):
        c.register_tokenizer("t2", 1)
    with pytest.raises(tc.SeqOrderError):
        c.register_tokenizer("t3", True)
    assert len(c.audit_log()) == before
    assert c.stats()["last_seq"] == 1


# ---------------------------------------------------------------- pieces

def _wp():
    c = tc.TokenCounter()
    c.register_tokenizer("wp", 1, kind="wordpiece")
    return c


def test_register_piece_roundtrip():
    c = _wp()
    c.register_piece("wp", "hello", 2)
    c.register_piece("wp", "he", 3)
    view = c.tokenizer("wp")
    assert view.vocab_size == 2
    assert view.verify()


def test_register_piece_bad_kind_duplicate_and_unknown_consume_seq():
    c, _ = _ws()
    with pytest.raises(tc.BadKindError):
        c.register_piece("tok", "hello", 2)
    c2 = _wp()
    c2.register_piece("wp", "hello", 2)
    with pytest.raises(tc.DuplicatePieceError):
        c2.register_piece("wp", "hello", 3)
    with pytest.raises(tc.UnknownTokenizerError):
        c2.register_piece("nope", "x", 4)
    with pytest.raises(tc.BadPieceError):
        c2.register_piece("wp", "", 5)
    assert [r["kind"] for r in c2.audit_log()].count("rejected") == 3
    assert [r["kind"] for r in c2.audit_log()].count("piece-registered") == 1


# ---------------------------------------------------------------- count

def test_count_whitespace_semantics():
    c, _ = _ws()
    r = c.count("tok", "hello   world\nfoo", 2)
    assert r.token_count == 3
    assert r.tokens == ("hello", "world", "foo")
    assert r.verify()


def test_count_char_semantics():
    c = tc.TokenCounter()
    c.register_tokenizer("ch", 1, kind="char")
    r = c.count("ch", "ab c", 2)
    assert r.token_count == 4
    assert r.tokens == ("a", "b", " ", "c")


def test_count_wordpiece_greedy_longest_match_and_digest_determinism():
    c = _wp()
    c.register_piece("wp", "hello", 2)
    c.register_piece("wp", "he", 3)
    c.register_piece("wp", "world", 4)
    r = c.count("wp", "helloworld", 5)
    assert r.tokens == ("hello", "world")  # longest match wins over "he"
    r2 = c.count("wp", "helloworld", 6)
    assert r2.digest == r.digest  # same ledger, same pin
    r3 = c.count("wp", "xyz", 7)
    assert r3.tokens == ("x", "y", "z")  # unknown chars emitted as-is


def test_count_bad_inputs_consume_seq():
    c, _ = _ws()
    with pytest.raises(tc.UnknownTokenizerError):
        c.count("nope", "hello", 2)
    with pytest.raises(tc.BadTextError):
        c.count("tok", b"bytes", 3)
    assert [r["kind"] for r in c.audit_log()].count("rejected") == 2


# ---------------------------------------------------------------- estimate

def test_estimate_pure_read_no_seq_consumed_no_audit():
    c, _ = _ws()
    before = len(c.audit_log())
    e1 = c.estimate("tok", "hello world", 2)
    e2 = c.estimate("tok", "hello world", 2)  # same seq twice: pure read
    assert e1.estimated_tokens == e2.estimated_tokens
    assert e1.char_count == 11
    assert e1.estimated_tokens == (11 + 5 - 1) // 5 == 3
    assert len(c.audit_log()) == before
    assert c.stats()["last_seq"] == 1  # no consumption
    with pytest.raises(tc.UnknownTokenizerError):
        c.estimate("nope", "x", 3)


# ---------------------------------------------------------------- truncate

def test_truncate_roundtrip_and_digest():
    c, _ = _ws()
    r = c.truncate("tok", "a b c d", 2, 2)
    assert r.truncated_text == "a b"
    assert r.truncated_tokens == ("a", "b")
    assert r.dropped_count == 2
    assert r.original_count == 4
    assert r.verify()


def test_truncate_fits_and_bad_max_tokens():
    c, _ = _ws()
    r = c.truncate("tok", "a b", 10, 2)
    assert r.truncated_text == "a b" and r.dropped_count == 0
    with pytest.raises(tc.BadMaxTokensError):
        c.truncate("tok", "a b", 0, 3)
    with pytest.raises(tc.BadMaxTokensError):
        c.truncate("tok", "a b", True, 4)
    with pytest.raises(tc.UnknownTokenizerError):
        c.truncate("nope", "a b", 2, 5)
    assert [x["kind"] for x in c.audit_log()].count("rejected") == 3


# ---------------------------------------------------------------- audit + main

def test_audit_shapes_and_text_leak_ban_and_bad_kind():
    c, _ = _ws()
    c.count("tok", "secret words here", 2)
    c.truncate("tok", "secret words here", 1, 3)
    for row in c.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        for key in row:
            assert key not in ("text", "tokens", "pieces", "raw", "payload",
                               "value")
    with pytest.raises(tc.AuditKindError):
        tc.token_counter_audit_event("nope")
    with pytest.raises(tc.AuditKindError):
        tc.token_counter_audit_event("counted", text="leak")


def test_main_self_check():
    p = subprocess.run([sys.executable, str(HERE / "token_counter.py")],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    assert "token-counter OK" in p.stdout
