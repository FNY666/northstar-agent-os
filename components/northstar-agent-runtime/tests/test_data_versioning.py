"""Tests for data_versioning: DVC/LakeFS-shaped snapshot bookkeeping."""

import ast
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data_versioning import (
    AUDIT_SCHEMA,
    DATA_VERSIONING_SCHEMA,
    DATA_VERSIONING_VERSION,
    DEFAULT_BRANCH,
    MERGE_STRATEGIES,
    AlreadyUpToDateError,
    BadBranchError,
    BadCommitError,
    BadMergeError,
    BadTagError,
    DataVersioning,
    DataVersioningError,
    DuplicateBranchError,
    DuplicateRepoError,
    DuplicateTagError,
    MergeConflictError,
    SeqOrderError,
    UnknownBranchError,
    UnknownCommitError,
    UnknownRepoError,
    UnknownTagError,
    data_versioning_audit_event,
)

MODULE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data_versioning.py"
)

_STDLIB_ALLOW = {
    "hashlib",
    "hmac",
    "json",
    "threading",
    "dataclasses",
    "typing",
    "__future__",
    "canonical_json",  # standard guarded fallback across the batch line
}


def fresh(seed="t"):
    return DataVersioning(seed=seed)


def init(dv, seq=0, repo_id="ds"):
    return dv.init_repo(repo_id, seq)


def commit(dv, seq, repo_id="ds", branch="main", digest="sha256:x", msg="m"):
    return dv.commit(repo_id, branch, digest, msg, seq)


# --- pins ------------------------------------------------------------------


def test_version_pins():
    assert DATA_VERSIONING_VERSION == "data-versioning.v1"
    assert DATA_VERSIONING_SCHEMA == "northstar.data-versioning.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert DEFAULT_BRANCH == "main"
    assert set(MERGE_STRATEGIES) == {"recursive", "ours", "theirs"}


def test_stdlib_only_ast():
    tree = ast.parse(open(MODULE_PATH).read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= _STDLIB_ALLOW, imported - _STDLIB_ALLOW


# --- init_repo / commit ------------------------------------------------------


def test_init_repo_roundtrip():
    dv = fresh()
    r = init(dv, 0)
    assert r.repo_id == "ds" and r.default_branch == "main"
    assert r.verify(seed="t")
    assert dv.head("ds", "main") is None
    try:
        init(dv, 1)
    except DuplicateRepoError:
        pass
    else:
        raise AssertionError("duplicate repo not refused")


def test_commit_chain_and_hash_chain():
    dv = fresh()
    init(dv, 0)
    c1 = commit(dv, 1, digest="sha256:aaa", msg="first")
    c2 = commit(dv, 2, digest="sha256:bbb", msg="second")
    assert c1.commit_id == "cmt-1" and c2.commit_id == "cmt-2"
    assert c1.parents == () and c2.parents == ("cmt-1",)
    assert c1.prev_digest == "genesis"
    assert c2.prev_digest == c1.digest
    assert c1.verify(seed="t") and c2.verify(seed="t")
    assert dv.head("ds", "main") == "cmt-2"
    # tamper-evidence: digest binds parents
    assert c2.digest != c1.digest


def test_commit_bad_inputs():
    dv = fresh()
    init(dv, 0)
    for bad in ("", "   ", None, 123):
        try:
            dv.commit("ds", "main", bad, "m", 1)
        except DataVersioningError:
            pass
        else:
            raise AssertionError(f"bad digest accepted: {bad!r}")
    try:
        dv.commit("ds", "main", "sha256:x", "x" * 1025, 2)
    except BadCommitError:
        pass
    else:
        raise AssertionError("oversize message accepted")
    try:
        dv.commit("nope", "main", "sha256:x", "m", 3)
    except UnknownRepoError:
        pass
    else:
        raise AssertionError("unknown repo accepted")
    try:
        dv.commit("ds", "nope", "sha256:x", "m", 4)
    except UnknownBranchError:
        pass
    else:
        raise AssertionError("unknown branch accepted")


# --- branch ------------------------------------------------------------------


def test_branch_create_and_commit_on_branch():
    dv = fresh()
    init(dv, 0)
    c1 = commit(dv, 1)
    b = dv.branch("ds", "feat", c1.commit_id, 2)
    assert b.name == "feat" and b.head_commit_id == "cmt-1"
    assert b.verify(seed="t")
    c2 = commit(dv, 3, branch="feat", digest="sha256:feat")
    assert c2.parents == ("cmt-1",) and dv.head("ds", "feat") == "cmt-2"
    assert dv.head("ds", "main") == "cmt-1"  # main untouched
    # default source: branch from default head
    b2 = dv.branch("ds", "hotfix", None, 4)
    assert b2.head_commit_id == "cmt-1"


def test_branch_errors():
    dv = fresh()
    init(dv, 0)
    c1 = commit(dv, 1)
    dv.branch("ds", "feat", c1.commit_id, 2)
    try:
        dv.branch("ds", "feat", c1.commit_id, 3)
    except DuplicateBranchError:
        pass
    else:
        raise AssertionError("duplicate branch accepted")
    try:
        dv.branch("ds", "bad name", c1.commit_id, 4)
    except DataVersioningError:
        pass
    else:
        raise AssertionError("whitespace branch name accepted")
    try:
        dv.branch("ds", "x", "cmt-999", 5)
    except UnknownCommitError:
        pass
    else:
        raise AssertionError("unknown commit accepted")
    # cannot branch from an empty repository
    dv2 = fresh()
    init(dv2, 0, repo_id="empty")
    try:
        dv2.branch("empty", "x", None, 1)
    except BadBranchError:
        pass
    else:
        raise AssertionError("branch from empty repo accepted")


# --- merge -------------------------------------------------------------------


def test_merge_fast_forward():
    dv = fresh()
    init(dv, 0)
    c1 = commit(dv, 1)
    dv.branch("ds", "feat", c1.commit_id, 2)
    c2 = commit(dv, 3, branch="feat", digest="sha256:b")
    m = dv.merge("ds", "feat", "main", 4)
    assert m.fast_forward is True
    assert m.result_commit_id == c2.commit_id
    assert m.base_commit_id == c1.commit_id
    assert m.verify(seed="t")
    assert dv.head("ds", "main") == c2.commit_id
    assert dv.head("ds", "feat") == c2.commit_id  # source untouched


def test_merge_three_way():
    dv = fresh()
    init(dv, 0)
    c1 = commit(dv, 1)
    dv.branch("ds", "feat", c1.commit_id, 2)
    c2 = commit(dv, 3, branch="feat", digest="sha256:b")
    c3 = commit(dv, 4, digest="sha256:c")
    m = dv.merge("ds", "feat", "main", 5, result_digest="sha256:merged")
    assert m.fast_forward is False
    assert m.base_commit_id == c1.commit_id
    mc = dv.commit_record(m.result_commit_id)
    assert mc.parents == (c3.commit_id, c2.commit_id)
    assert mc.dataset_digest == "sha256:merged"
    assert mc.message == "Merge branch 'feat' into 'main'"
    assert mc.verify(seed="t") and m.verify(seed="t")
    assert dv.head("ds", "main") == m.result_commit_id


def test_merge_conflict_refused():
    dv = fresh()
    init(dv, 0)
    c1 = commit(dv, 1)
    dv.branch("ds", "feat", c1.commit_id, 2)
    commit(dv, 3, branch="feat", digest="sha256:b")
    commit(dv, 4, digest="sha256:c")
    try:
        dv.merge("ds", "feat", "main", 5, conflicts=["data/train.csv"])
    except MergeConflictError:
        pass
    else:
        raise AssertionError("conflicted merge accepted")
    # heads unchanged after refusal
    assert dv.head("ds", "main") == "cmt-3"
    assert dv.head("ds", "feat") == "cmt-2"


def test_merge_self_merge_and_bad_strategy():
    dv = fresh()
    init(dv, 0)
    commit(dv, 1)
    try:
        dv.merge("ds", "main", "main", 2)
    except BadMergeError:
        pass
    else:
        raise AssertionError("self-merge accepted")
    try:
        dv.merge("ds", "main", "main", 3, strategy="nope")
    except BadMergeError:
        pass
    else:
        raise AssertionError("bad strategy accepted")
    # note: every commit chains back to the repo root through the public
    # API, so "no common ancestor" is defensive-only and untestable here.


def test_merge_already_up_to_date():
    dv = fresh()
    init(dv, 0)
    c1 = commit(dv, 1)
    dv.branch("ds", "feat", c1.commit_id, 2)
    try:
        dv.merge("ds", "feat", "main", 3)
    except AlreadyUpToDateError:
        pass
    else:
        raise AssertionError("up-to-date merge accepted")


# --- tag ---------------------------------------------------------------------


def test_tag_roundtrip_and_duplicate():
    dv = fresh()
    init(dv, 0)
    c1 = commit(dv, 1)
    t = dv.tag("ds", "v1.0", c1.commit_id, 2)
    assert t.tag == "v1.0" and t.commit_id == "cmt-1"
    assert t.verify(seed="t")
    assert dv.tag_record("ds", "v1.0").commit_id == "cmt-1"
    try:
        dv.tag("ds", "v1.0", c1.commit_id, 3)
    except DuplicateTagError:
        pass
    else:
        raise AssertionError("duplicate tag accepted")
    try:
        dv.tag("ds", "v2.0", "cmt-999", 4)
    except UnknownCommitError:
        pass
    else:
        raise AssertionError("tag of unknown commit accepted")
    try:
        dv.tag_record("ds", "nope")
    except UnknownTagError:
        pass
    else:
        raise AssertionError("unknown tag lookup accepted")


# --- seq discipline ------------------------------------------------------------


def test_seq_discipline():
    dv = fresh()
    init(dv, 0)
    for bad in (True, -1, "1", 1.0):
        try:
            commit(dv, bad)
        except DataVersioningError:
            pass
        else:
            raise AssertionError(f"bad seq accepted: {bad!r}")
    try:
        commit(dv, 0)  # rewind
    except SeqOrderError:
        pass
    else:
        raise AssertionError("seq rewind accepted")
    # failed mutation consumes its seq: next good seq must exceed the failed one
    try:
        dv.commit("ds", "nope", "sha256:x", "m", 1)
    except UnknownBranchError:
        pass
    c = commit(dv, 2)
    assert c.commit_id == "cmt-1"
    assert dv.as_dict()["last_seq"] == 2


# --- views ---------------------------------------------------------------------


def test_history_view():
    dv = fresh()
    init(dv, 0)
    commit(dv, 1, msg="one")
    commit(dv, 2, msg="two")
    commit(dv, 3, msg="three")
    h = dv.history("ds", "main", 4)
    assert [c.message for c in h] == ["three", "two", "one"]
    assert len(dv.history("ds", "main", 5, limit=2)) == 2
    # read does not consume seq
    assert dv.as_dict()["last_seq"] == 3
    # empty branch history
    dv2 = fresh()
    init(dv2, 0, repo_id="e")
    assert dv2.history("e", "main", 1) == ()


def test_merge_base_view():
    dv = fresh()
    init(dv, 0)
    c1 = commit(dv, 1)
    dv.branch("ds", "feat", c1.commit_id, 2)
    c2 = commit(dv, 3, branch="feat", digest="sha256:b")
    assert dv.merge_base("ds", "feat", "main", 4) == c1.commit_id
    dv.merge("ds", "feat", "main", 5)
    # feat fully merged: base is feat's own head
    assert dv.merge_base("ds", "feat", "main", 6) == c2.commit_id


# --- audit ---------------------------------------------------------------------


def test_audit_shapes():
    dv = fresh()
    init(dv, 0)
    c1 = commit(dv, 1, digest="sha256:aaa", msg="ingest")
    dv.branch("ds", "feat", c1.commit_id, 2)
    dv.tag("ds", "v1", c1.commit_id, 3)
    try:
        dv.commit("ds", "nope", "sha256:x", "m", 4)
    except UnknownBranchError:
        pass
    kinds = [e["kind"] for e in dv.audit_log()]
    assert kinds == [
        "data-versioning.repo-initialized",
        "data-versioning.committed",
        "data-versioning.branch-created",
        "data-versioning.tagged",
        "data-versioning.rejected",
    ]
    for e in dv.audit_log():
        assert e["schema"] == AUDIT_SCHEMA
        assert e["module"] == "data_versioning"
        assert e["module_version"] == DATA_VERSIONING_VERSION
    # dataset bytes never cross the audit boundary: only digests + ids
    committed = dv.audit_log()[1]
    assert committed["detail"]["dataset_digest"] == "sha256:aaa"
    assert "content" not in committed["detail"] and "bytes" not in committed["detail"]
    try:
        data_versioning_audit_event("nope.kind", 9)
    except DataVersioningError:
        pass
    else:
        raise AssertionError("bad audit kind accepted")


def test_main_selfcheck():
    import data_versioning as mod

    mod.main()
