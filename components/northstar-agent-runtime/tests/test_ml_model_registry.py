"""Tests for ml_model_registry: MLflow-shaped run-to-registry lifecycle."""

import ast
import json
import subprocess
import sys

import pytest

import ml_model_registry
from ml_model_registry import (
    MLModelRegistry,
    MLModelRegistryError,
    STAGE_STAGING,
    STAGE_PRODUCTION,
    STAGE_ARCHIVED,
    STAGE_UNSTAGED,
    ml_model_registry_audit_event,
    ML_MODEL_REGISTRY_VERSION,
    ML_MODEL_REGISTRY_SCHEMA,
)

DIGEST_1 = "sha256:" + "ab" * 32
DIGEST_2 = "sha256:" + "cd" * 32


@pytest.fixture()
def reg():
    return MLModelRegistry()


@pytest.fixture()
def seq():
    state = {"n": 0}

    def _nxt():
        state["n"] += 1
        return state["n"]

    return _nxt


def test_version_and_schema_pins():
    assert ML_MODEL_REGISTRY_VERSION == "ml-model-registry.v1"
    assert ML_MODEL_REGISTRY_SCHEMA == "northstar.ml-model-registry.v1"


def test_stdlib_only():
    tree = ast.parse(open(ml_model_registry.__file__).read())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
    }
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= allowed, imported - allowed


def test_register_roundtrip(reg, seq):
    record = reg.register("m", seq(), run_id="run-1", source="s3://b/a")
    assert record.name == "m"
    assert record.run_id == "run-1"
    assert record.source == "s3://b/a"
    assert record.verify()
    assert reg.model("m") is record
    assert reg.model_names() == ("m",)


def test_register_duplicate_fails_closed(reg, seq):
    reg.register("m", seq())
    with pytest.raises(ml_model_registry.DuplicateModelError):
        reg.register("m", seq())
    # failed mutation consumed its seq: next claim at last seq is a rewind
    with pytest.raises(ml_model_registry.SeqOrderError):
        reg.register("n", 1)


def test_register_bad_inputs(reg, seq):
    with pytest.raises(ml_model_registry.BadNameError):
        reg.register("", seq())
    with pytest.raises(ml_model_registry.BadNameError):
        reg.register(123, seq() + 1)
    with pytest.raises(ml_model_registry.BadRunError):
        reg.register("ok", seq() + 2, run_id=42)
    with pytest.raises(ml_model_registry.BadSourceError):
        reg.register("ok", seq() + 3, source=42)


def test_version_auto_increment(reg, seq):
    reg.register("m", seq())
    v1 = reg.version("m", seq(), artifact_digest=DIGEST_1, source_run_id="run-1")
    v2 = reg.version("m", seq())
    assert v1.version == 1
    assert v2.version == 2
    assert v1.verify() and v2.verify()
    assert v1.stage == STAGE_UNSTAGED
    assert v1.artifact_digest == DIGEST_1
    assert v2.artifact_digest == ""
    assert [r.version for r in reg.versions("m")] == [1, 2]
    assert reg.version_record("m", 1) is v1


def test_version_unknown_model(reg, seq):
    with pytest.raises(ml_model_registry.UnknownModelError):
        reg.version("ghost", seq(), artifact_digest=DIGEST_1)


def test_version_bad_digest(reg, seq):
    reg.register("m", seq())
    with pytest.raises(ml_model_registry.BadDigestError):
        reg.version("m", seq(), artifact_digest="not-a-digest")
    with pytest.raises(ml_model_registry.BadDigestError):
        reg.version("m", seq(), artifact_digest="sha256:" + "zz" * 32)


def test_stage_lifecycle(reg, seq):
    reg.register("m", seq())
    v1 = reg.version("m", seq())
    st = reg.stage("m", 1, STAGE_STAGING, seq())
    assert st.verify()
    assert st.from_stage == STAGE_UNSTAGED and st.to_stage == STAGE_STAGING
    reg.stage("m", 1, STAGE_PRODUCTION, seq())
    assert reg.production_version("m") == 1
    assert reg.version_record("m", 1).stage == STAGE_PRODUCTION
    reg.stage("m", 1, STAGE_ARCHIVED, seq())
    assert reg.production_version("m") is None
    reg.stage("m", 1, STAGE_STAGING, seq())
    assert reg.version_record("m", 1).stage == STAGE_STAGING


def test_stage_illegal_move_fails_closed(reg, seq):
    reg.register("m", seq())
    reg.version("m", seq())
    with pytest.raises(ml_model_registry.StageConflictError):
        reg.stage("m", 1, STAGE_PRODUCTION, seq())  # None -> Production
    with pytest.raises(ml_model_registry.BadStageError):
        reg.stage("m", 1, "Nonsense", seq())
    # None -> Archived is also illegal
    with pytest.raises(ml_model_registry.StageConflictError):
        reg.stage("m", 1, STAGE_ARCHIVED, seq())


def test_stage_competing_production(reg, seq):
    reg.register("m", seq())
    reg.version("m", seq())
    reg.version("m", seq())
    reg.stage("m", 1, STAGE_STAGING, seq())
    reg.stage("m", 1, STAGE_PRODUCTION, seq())
    reg.stage("m", 2, STAGE_STAGING, seq())
    # without archive_existing, competing production fails closed
    with pytest.raises(ml_model_registry.StageConflictError):
        reg.stage("m", 2, STAGE_PRODUCTION, seq())
    reg.stage("m", 2, STAGE_PRODUCTION, seq(), archive_existing=True)
    assert reg.production_version("m") == 2
    assert reg.version_record("m", 1).stage == STAGE_ARCHIVED


def test_seq_ordering(reg, seq):
    reg.register("m", seq())
    with pytest.raises(ml_model_registry.SeqOrderError):
        reg.version("m", 1)  # rewind
    with pytest.raises(ml_model_registry.SeqOrderError):
        reg.version("m", True)
    with pytest.raises(ml_model_registry.SeqOrderError):
        reg.register("n", -1)


def test_audit_shapes_and_leak_ban(reg, seq):
    reg.register("m", seq())
    reg.version("m", seq(), artifact_digest=DIGEST_1)
    reg.stage("m", 1, STAGE_STAGING, seq())
    kinds = [row["kind"] for row in reg.audit_log()]
    assert kinds == [
        "ml-model.registered",
        "ml-model.versioned",
        "ml-model.staged",
    ]
    for row in reg.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == ML_MODEL_REGISTRY_VERSION
        for banned in ("payload", "value", "raw", "metadata", "bytes"):
            assert banned not in row, banned
    with pytest.raises(ml_model_registry.AuditKindError):
        ml_model_registry_audit_event("bogus", "m", 1)


def test_rejected_audit_row(reg, seq):
    with pytest.raises(ml_model_registry.UnknownModelError):
        reg.version("ghost", seq())
    last = reg.audit_log()[-1]
    assert last["kind"] == "ml-model.rejected"
    assert last["error"] == "UnknownModelError"


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, ml_model_registry.__file__],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ml-model-registry OK" in proc.stdout
