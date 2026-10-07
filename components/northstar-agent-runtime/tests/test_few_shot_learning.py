"""Targeted tests for few_shot_learning.py (15 tests)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import few_shot_learning as fsl
from few_shot_learning import (
    FewShotLearning,
    few_shot_learning_audit_event,
    VERSION,
    SCHEMA,
    KIND_EXAMPLE_REGISTERED,
    KIND_SELECTED,
    KIND_PROMPT_BUILT,
    KIND_REJECTED,
    FewShotLearningError,
    BadExampleError,
    DuplicateExampleError,
    BadInputError,
    BadOutputError,
    BadKError,
    BadTagError,
    BadPromptError,
    UnknownSelectionError,
    SeqOrderError,
    AuditKindError,
)

MODULE = Path(fsl.__file__)


# --------------------------------------------------------------------------
# 1. version / schema pins
# --------------------------------------------------------------------------

def test_version_schema_pins():
    assert VERSION == "few-shot-learning.v1"
    assert SCHEMA == "northstar.few-shot-learning.v1"
    rec = FewShotLearning().example("e1", "i", "o", seq=1)
    assert rec.as_dict()["schema"] == SCHEMA


# --------------------------------------------------------------------------
# 2. stdlib-only AST check
# --------------------------------------------------------------------------

def test_stdlib_only_imports():
    tree = ast.parse(MODULE.read_text())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "__future__",
        "json", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# --------------------------------------------------------------------------
# 3. example roundtrip + digest verify
# --------------------------------------------------------------------------

def test_example_roundtrip_verify():
    f = FewShotLearning()
    rec = f.example("ex-a", "2+2", "4", seq=1, tags=("math",))
    assert rec.example_id == "ex-a"
    assert rec.input_digest.startswith("sha256:")
    assert rec.output_digest.startswith("sha256:")
    assert rec.tags == ("math",)
    assert rec.verify()
    assert f.example_record("ex-a", seq=2).verify()


# --------------------------------------------------------------------------
# 4. duplicate + seq-burn + rejected row
# --------------------------------------------------------------------------

def test_duplicate_consumes_seq_books_rejected():
    f = FewShotLearning()
    f.example("e1", "i", "o", seq=1)
    with pytest.raises(DuplicateExampleError):
        f.example("e1", "i2", "o2", seq=2)
    kinds = [e["kind"] for e in f.audit_log()]
    assert kinds == [KIND_EXAMPLE_REGISTERED, KIND_REJECTED]
    assert f.stats(3)["rejected"] == 1
    # seq 2 was consumed: next mutation must use seq 3
    with pytest.raises(SeqOrderError):
        f.example("e2", "i", "o", seq=2)
    f.example("e2", "i", "o", seq=3)


# --------------------------------------------------------------------------
# 5. bad-input table
# --------------------------------------------------------------------------

def test_bad_input_table():
    f = FewShotLearning()
    bads = [
        ("", "i", "o", BadExampleError),
        ("has space", "i", "o", BadExampleError),
        ("e1", "", "o", BadInputError),
        ("e1", "i", "", BadOutputError),
        (123, "i", "o", BadExampleError),
        ("e1", 123, "o", BadInputError),
    ]
    seq = 1
    for eid, inp, outp, exc in bads:
        with pytest.raises(exc):
            f.example(eid, inp, outp, seq=seq)
        seq += 1
    with pytest.raises(BadTagError):
        f.example("e9", "i", "o", seq=seq, tags=("ok", "ok"))
    with pytest.raises(BadTagError):
        f.example("e9", "i", "o", seq=seq + 1, tags=("has space",))


# --------------------------------------------------------------------------
# 6. select roundtrip: k, order, tag filter
# --------------------------------------------------------------------------

def test_select_roundtrip_order_and_tags():
    f = FewShotLearning()
    f.example("ex-2", "b", "B", seq=1, tags=("t2",))
    f.example("ex-1", "a", "A", seq=2, tags=("t1",))
    f.example("ex-3", "c", "C", seq=3, tags=("t1", "t2"))
    sel = f.select(seq=4, k=10)
    assert sel.selection_id == "sel-1"
    assert sel.example_ids == ("ex-1", "ex-2", "ex-3")
    assert sel.verify()
    sel2 = f.select(seq=5, k=2, tags=("t1",))
    assert sel2.example_ids == ("ex-1", "ex-3")
    sel3 = f.select(seq=6, k=5, tags=("nope",))
    assert sel3.example_ids == ()  # empty-as-data
    sel4 = f.select(seq=7, k=0)
    assert sel4.example_ids == ()


# --------------------------------------------------------------------------
# 7. prompt renders deterministically in selection order
# --------------------------------------------------------------------------

def test_prompt_rendering():
    f = FewShotLearning()
    f.example("ex-1", "2+2", "4", seq=1)
    f.example("ex-2", "3*3", "9", seq=2)
    sel = f.select(seq=3, k=2)
    rec, text = f.prompt(seq=4, selection_id=sel.selection_id,
                         instruction="Solve:", prefix="Input: 1+1\nOutput:")
    assert rec.verify()
    assert rec.example_count == 2
    assert text == ("Solve:\n\nInput: 2+2\nOutput: 4\n\n"
                    "Input: 3*3\nOutput: 9\n\nInput: 1+1\nOutput:")
    # same ledger, same selection -> byte-identical render
    f2 = FewShotLearning()
    f2.example("ex-1", "2+2", "4", seq=1)
    f2.example("ex-2", "3*3", "9", seq=2)
    sel_b = f2.select(seq=3, k=2)
    rec_b, text_b = f2.prompt(seq=4, selection_id=sel_b.selection_id,
                              instruction="Solve:", prefix="Input: 1+1\nOutput:")
    assert text_b == text
    assert rec_b.rendered_digest == rec.rendered_digest


# --------------------------------------------------------------------------
# 8. prompt bare-bones (no instruction / prefix)
# --------------------------------------------------------------------------

def test_prompt_bare_and_unknown_selection():
    f = FewShotLearning()
    f.example("ex-1", "a", "b", seq=1)
    sel = f.select(seq=2, k=1)
    rec, text = f.prompt(seq=3, selection_id=sel.selection_id)
    assert text == "Input: a\nOutput: b"
    assert rec.example_count == 1
    with pytest.raises(UnknownSelectionError):
        f.prompt(seq=4, selection_id="sel-99")


# --------------------------------------------------------------------------
# 9. bad prompt inputs fail closed
# --------------------------------------------------------------------------

def test_bad_prompt_inputs():
    f = FewShotLearning()
    f.example("ex-1", "a", "b", seq=1)
    sel = f.select(seq=2, k=1)
    with pytest.raises(BadPromptError):
        f.prompt(seq=3, selection_id=sel.selection_id, instruction=123)
    with pytest.raises(BadPromptError):
        f.prompt(seq=4, selection_id=sel.selection_id, prefix=b"x")
    with pytest.raises(BadKError):
        f.select(seq=5, k=-1)
    with pytest.raises(BadKError):
        f.select(seq=6, k=True)


# --------------------------------------------------------------------------
# 10. seq ordering: rewind bare, bool/str refused, failed consumes
# --------------------------------------------------------------------------

def test_seq_ordering():
    f = FewShotLearning()
    f.example("e1", "i", "o", seq=1)
    with pytest.raises(SeqOrderError):
        f.example("e2", "i", "o", seq=1)  # rewind, bare (no audit row)
    with pytest.raises(SeqOrderError):
        f.select(seq=True)
    with pytest.raises(SeqOrderError):
        f.select(seq="5")
    with pytest.raises(SeqOrderError):
        f.example("e3", "i", "o", seq=-1)
    # rewind did not consume: seq 2 still open
    f.example("e2", "i", "o", seq=2)
    assert f.stats(3)["examples"] == 2


# --------------------------------------------------------------------------
# 11. pure-read views consume no seq and write no audit rows
# --------------------------------------------------------------------------

def test_view_read_purity():
    f = FewShotLearning()
    f.example("e1", "i", "o", seq=1)
    before = len(f.audit_log())
    assert f.example_ids(seq=2) == ("e1",)
    assert f.example_record("e1", seq=2).verify()
    assert f.stats(seq=2)["examples"] == 1
    assert len(f.audit_log()) == before
    # rewind allowed on reads
    assert f.stats(seq=1)["examples"] == 1


# --------------------------------------------------------------------------
# 12. audit shapes + raw-text leak ban + bad kind
# --------------------------------------------------------------------------

def test_audit_shapes_and_leak_ban():
    f = FewShotLearning()
    f.example("e1", "secret-input", "secret-output", seq=1)
    sel = f.select(seq=2, k=1)
    f.prompt(seq=3, selection_id=sel.selection_id)
    raw = "\n".join(str(e) for e in f.audit_log())
    assert "secret-input" not in raw
    assert "secret-output" not in raw
    kinds = [e["kind"] for e in f.audit_log()]
    assert kinds == [KIND_EXAMPLE_REGISTERED, KIND_SELECTED, KIND_PROMPT_BUILT]
    for e in f.audit_log():
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "few-shot-learning"
    with pytest.raises(AuditKindError):
        few_shot_learning_audit_event("bogus", 1, {})
    with pytest.raises(AuditKindError):
        few_shot_learning_audit_event(KIND_SELECTED, 1, {"input": "x"})
    f2 = FewShotLearning()
    f2.example("e1", "i", "o", seq=1)
    assert f2.audit_log()[0]["kind"] == KIND_EXAMPLE_REGISTERED


# --------------------------------------------------------------------------
# 13. concurrency smoke
# --------------------------------------------------------------------------

def test_concurrency_smoke():
    f = FewShotLearning()
    errs = []

    def worker(n):
        try:
            for i in range(5):
                f.example(f"w{n}-{i}", "i", "o", seq=n * 100 + i + 1)
        except Exception as exc:  # noqa: BLE001
            errs.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs
    assert f.stats(99999)["examples"] == 20


# --------------------------------------------------------------------------
# 14. frozen records
# --------------------------------------------------------------------------

def test_records_frozen():
    f = FewShotLearning()
    rec = f.example("e1", "i", "o", seq=1)
    with pytest.raises(Exception):
        rec.example_id = "mutated"
    sel = f.select(seq=2, k=1)
    with pytest.raises(Exception):
        sel.k = 99


# --------------------------------------------------------------------------
# 15. main() subprocess check
# --------------------------------------------------------------------------

def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True, text=True, timeout=60, cwd=str(MODULE.parent),
    )
    assert proc.returncode == 0, proc.stderr
    assert "few-shot-learning OK" in proc.stdout
