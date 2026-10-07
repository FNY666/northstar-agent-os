"""Tests for data_catalog (Amundsen-shaped dataset/schema ledger)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from data_catalog import (
    AUDIT_SCHEMA,
    COLUMN_TYPES,
    DATA_CATALOG_SCHEMA,
    DATA_CATALOG_VERSION,
    AuditKindError,
    BadColumnError,
    BadDatasetError,
    BadSchemaError,
    BadTagError,
    DataCatalog,
    DatasetRecord,
    DuplicateDatasetError,
    RetiredDatasetError,
    SeqOrderError,
    UnknownDatasetError,
    data_catalog_audit_event,
)

RUNTIME = Path(__file__).resolve().parents[1]


def make_catalog():
    return DataCatalog()


def register(catalog, seq=1, **kwargs):
    args = {
        "dataset_id": "ds.analytics.sessions",
        "name": "Sessions",
        "seq": seq,
        "columns": (("session_id", "string"), ("user_id", "string")),
        "tags": ("analytics",),
        "owner": "data-eng",
        "description": "Web session events",
    }
    args.update(kwargs)
    return catalog.dataset(**args)


def test_version_and_schema_pins():
    assert DATA_CATALOG_VERSION == "data-catalog.v1"
    assert DATA_CATALOG_SCHEMA == "northstar.data-catalog.v1"
    assert COLUMN_TYPES == (
        "string", "integer", "number", "boolean", "timestamp", "date", "array", "struct",
    )


def test_stdlib_only():
    tree = ast.parse((RUNTIME / "data_catalog.py").read_text())
    allowed = {
        "__future__", "hashlib", "re", "threading", "dataclasses",
        "typing", "json", "builtins", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_dataset_roundtrip_and_pins():
    catalog = make_catalog()
    record = register(catalog)
    assert record.verify()
    assert isinstance(record, DatasetRecord)
    assert record.digest.startswith("sha256:")
    assert record.schema_digest.startswith("sha256:")
    assert record.tags == ("analytics",)
    view = catalog.dataset_view("ds.analytics.sessions", 2)
    assert view.dataset_id == "ds.analytics.sessions"


def test_dataset_duplicate_and_bad_inputs():
    catalog = make_catalog()
    register(catalog)
    with pytest.raises(DuplicateDatasetError):
        register(catalog, seq=2)
    with pytest.raises(BadDatasetError):
        register(catalog, seq=3, dataset_id="")
    with pytest.raises(BadDatasetError):
        register(catalog, seq=4, dataset_id="has space")
    with pytest.raises(BadDatasetError):
        register(catalog, seq=5, dataset_id="has\ttab")
    # failed mutations consume their seqs; fresh seqs keep working
    record = register(catalog, seq=6, dataset_id="ds.other", name="Other")
    assert record.dataset_id == "ds.other"


def test_bad_columns_and_tags():
    catalog = make_catalog()
    with pytest.raises(BadColumnError):
        register(catalog, seq=1, columns=(("a", "blob"),))
    with pytest.raises(BadColumnError):
        register(catalog, seq=2, columns=(("a", "string"), ("a", "string")))
    with pytest.raises(BadSchemaError):
        register(catalog, seq=3, columns="not-a-sequence")
    with pytest.raises(BadTagError):
        register(catalog, seq=4, tags=("",))


def test_schema_view_pure_read():
    catalog = make_catalog()
    register(catalog)
    report = catalog.schema("ds.analytics.sessions", 2)
    assert report.columns == (("session_id", "string"), ("user_id", "string"))
    assert report.schema_digest.startswith("sha256:")
    # read views do not consume seq: same seq again is fine
    report2 = catalog.schema("ds.analytics.sessions", 2)
    assert report2 == report
    with pytest.raises(UnknownDatasetError):
        catalog.schema("ds.nope", 3)


def test_search_semantics():
    catalog = make_catalog()
    register(catalog, seq=1)
    register(catalog, seq=2, dataset_id="ds.billing.invoices", name="Invoices",
             description="Billing invoice rows", tags=("billing",), owner="fin-ops")
    found = catalog.search("session", 3)
    assert found.dataset_ids == ("ds.analytics.sessions",)
    assert catalog.search("INVOICE", 4).dataset_ids == ("ds.billing.invoices",)
    assert catalog.search("session", 5, tags=("billing",)).dataset_ids == ()
    assert catalog.search("invoice", 6, owner="fin-ops").dataset_ids == (
        "ds.billing.invoices",)
    assert catalog.search("nothing-here", 7).dataset_ids == ()


def test_search_pure_read_no_seq_consumption():
    catalog = make_catalog()
    register(catalog)
    first = catalog.search("session", 2)
    second = catalog.search("session", 2)
    assert first == second


def test_update_schema_evolution():
    catalog = make_catalog()
    register(catalog)
    update = catalog.update_schema("ds.analytics.sessions", 2, (("session_id", "string"),))
    assert update.verify()
    assert update.old_schema_digest != update.schema_digest
    report = catalog.schema("ds.analytics.sessions", 3)
    assert report.columns == (("session_id", "string"),)
    history = catalog.schema_history("ds.analytics.sessions", 4)
    assert len(history) == 1
    with pytest.raises(UnknownDatasetError):
        catalog.update_schema("ds.nope", 5, (("a", "string"),))


def test_retire_terminality():
    catalog = make_catalog()
    register(catalog)
    retire = catalog.retire("ds.analytics.sessions", 2, reason="deprecated")
    assert retire.reason == "deprecated"
    with pytest.raises(RetiredDatasetError):
        catalog.update_schema("ds.analytics.sessions", 3, (("a", "string"),))
    with pytest.raises(RetiredDatasetError):
        register(catalog, seq=4)
    assert catalog.dataset_ids(5) == ()
    assert catalog.dataset_ids(6, include_retired=True) == ("ds.analytics.sessions",)
    assert catalog.search("session", 7).dataset_ids == ()
    assert catalog.search("session", 8, include_retired=True).dataset_ids == (
        "ds.analytics.sessions",)


def test_seq_ordering_and_failed_mutation_consumes_seq():
    catalog = make_catalog()
    register(catalog, seq=1)
    with pytest.raises(SeqOrderError):
        catalog.dataset("ds.other", "Other", 1)
    with pytest.raises(SeqOrderError):
        catalog.dataset("ds.other", "Other", True)
    # bad payload consumes seq 2, so seq 2 is dead; next valid is 3
    with pytest.raises(BadColumnError):
        register(catalog, seq=2, dataset_id="ds.other", columns=(("a", "blob"),))
    with pytest.raises(SeqOrderError):
        register(catalog, seq=2, dataset_id="ds.other")


def test_audit_shapes_and_leak_ban():
    catalog = make_catalog()
    register(catalog)
    catalog.update_schema("ds.analytics.sessions", 2, (("session_id", "string"),))
    log = catalog.audit_log()
    kinds = [e["kind"] for e in log]
    assert kinds[0] == "dataset-registered"
    assert kinds[1] == "schema-updated"
    for event in log:
        assert event["schema"] == AUDIT_SCHEMA
        for banned in ("name", "description", "tags", "columns", "payload", "value", "raw"):
            assert banned not in event, banned
    with pytest.raises(AuditKindError):
        data_catalog_audit_event("bogus-kind", seq=9)


def test_stats_view():
    catalog = make_catalog()
    register(catalog, seq=1)
    register(catalog, seq=2, dataset_id="ds.other", name="Other")
    catalog.retire("ds.other", 3)
    stats = catalog.stats(4)
    assert stats == {"datasets": 2, "retired": 1, "live": 1}


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, str(RUNTIME / "data_catalog.py")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "data-catalog OK" in result.stdout


def test_cross_instance_digest_determinism():
    a = make_catalog()
    b = make_catalog()
    ra = register(a)
    rb = register(b)
    assert ra.digest == rb.digest
    assert ra.schema_digest == rb.schema_digest
