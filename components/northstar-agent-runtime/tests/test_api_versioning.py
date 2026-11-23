"""Tests for api_versioning — Stripe-shaped lifecycle bookkeeping."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from api_versioning import (
    APIVersioning,
    API_VERSIONING_SCHEMA,
    API_VERSIONING_VERSION,
    AUDIT_SCHEMA,
    STATUS_CURRENT,
    STATUS_DEPRECATED,
    STATUS_SUNSET,
    APIVersioningError,
    BadLifecycleError,
    BadMigrationError,
    BadVersionError,
    DuplicateMigrationError,
    DuplicateVersionError,
    SeqOrderError,
    UnknownVersionError,
    api_versioning_audit_event,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "api_versioning.py"
V1 = "2025-06-01"
V2 = "2026-10-08.acacia"
DIGEST = "sha256:" + "ab" * 32


def _mgr_two_versions() -> APIVersioning:
    mgr = APIVersioning()
    mgr.register(V1, seq=1)
    mgr.register(V2, seq=2)
    return mgr


# 1. Version/schema pins exist.
def test_version_and_schema_pins():
    assert API_VERSIONING_VERSION == "api-versioning.v1"
    assert API_VERSIONING_SCHEMA == "northstar.api-versioning.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


# 2. Module is stdlib-only.
def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib", "json", "re", "threading",
        "dataclasses", "typing", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3. Register roundtrip.
def test_register_roundtrip():
    mgr = APIVersioning()
    rec = mgr.register(V2, seq=1, changes=("added fields",))
    assert rec.verify()
    assert rec.version_id == V2
    assert rec.status == STATUS_CURRENT
    assert rec.changes == ("added fields",)
    assert mgr.version(V2) is rec


# 4. Bad version ids refused.
def test_register_bad_version_ids():
    mgr = APIVersioning()
    seq = 0
    for bad in ("", "2026-13-01", "2026-10-8", "v2", 20261008, "2026-10-08.Elm",
                "2026-10-08.zebra", "2026-00-01"):
        seq += 1
        with pytest.raises(BadVersionError):
            mgr.register(bad, seq=seq)
    assert mgr.version_ids() == ()


# 5. Duplicate registration refused.
def test_register_duplicate():
    mgr = APIVersioning()
    mgr.register(V1, seq=1)
    with pytest.raises(DuplicateVersionError):
        mgr.register(V1, seq=2)
    assert mgr.version_ids() == (V1,)


# 6. Deprecate roundtrip with sunset seq and successor.
def test_deprecate_roundtrip():
    mgr = _mgr_two_versions()
    dep = mgr.deprecate(V1, seq=3, sunset_seq=100, successor=V2, note="move off")
    assert dep.verify()
    assert mgr.status_of(V1) == STATUS_DEPRECATED
    assert mgr.deprecated_ids() == (V1,)
    assert mgr.current_ids() == (V2,)


# 7. Deprecate bad transitions refused.
def test_deprecate_bad_transitions():
    mgr = APIVersioning()
    with pytest.raises(UnknownVersionError):
        mgr.deprecate(V1, seq=1)
    mgr.register(V1, seq=2)
    with pytest.raises(BadLifecycleError):
        mgr.deprecate(V1, seq=3, sunset_seq=1)  # sunset not after deprecation
    with pytest.raises(UnknownVersionError):
        mgr.deprecate(V1, seq=4, successor="2027-01-01")  # unknown successor
    mgr.deprecate(V1, seq=5)
    with pytest.raises(BadLifecycleError):
        mgr.deprecate(V1, seq=6)  # already deprecated


# 8. Migrate roundtrip.
def test_migrate_roundtrip():
    mgr = _mgr_two_versions()
    rec = mgr.migrate(V1, V2, seq=3, transform_digest=DIGEST)
    assert rec.verify()
    assert rec.direction == "forward"
    assert mgr.migration(V1, V2).digest == rec.digest
    assert mgr.migration_pairs() == ((V1, V2),)


# 9. Migrate bad pairs refused.
def test_migrate_bad_pairs():
    mgr = _mgr_two_versions()
    with pytest.raises(BadMigrationError):
        mgr.migrate(V1, V1, seq=3, transform_digest=DIGEST)  # self-migration
    with pytest.raises(BadMigrationError):
        mgr.migrate(V1, V2, seq=4, transform_digest="nope")  # bad digest
    with pytest.raises(UnknownVersionError):
        mgr.migrate(V1, "2027-01-01", seq=5, transform_digest=DIGEST)
    mgr.migrate(V1, V2, seq=6, transform_digest=DIGEST)
    with pytest.raises(DuplicateMigrationError):
        mgr.migrate(V1, V2, seq=7, transform_digest=DIGEST)
    # Sunset versions cannot be migrated to/from.
    mgr.deprecate(V1, seq=8)
    mgr.sunset(V1, seq=9)
    with pytest.raises(BadMigrationError):
        mgr.migrate(V2, V1, seq=10, transform_digest=DIGEST)


# 10. Sunset roundtrip and terminality.
def test_sunset_roundtrip_and_terminal():
    mgr = _mgr_two_versions()
    with pytest.raises(BadLifecycleError):
        mgr.sunset(V1, seq=3)  # current, not deprecated
    mgr.deprecate(V1, seq=4)
    rec = mgr.sunset(V1, seq=5, note="retired")
    assert rec.verify()
    assert mgr.status_of(V1) == STATUS_SUNSET
    assert mgr.sunset_ids() == (V1,)
    with pytest.raises(BadLifecycleError):
        mgr.sunset(V1, seq=6)  # already sunset


# 11. Seq ordering and failed-mutation-consumes-seq.
def test_seq_ordering():
    mgr = APIVersioning()
    mgr.register(V1, seq=1)
    with pytest.raises(SeqOrderError):
        mgr.register(V2, seq=1)  # rewind
    with pytest.raises(BadVersionError):
        mgr.register(True, seq=2)  # bool refused; still consumes seq 2
    with pytest.raises(SeqOrderError):
        mgr.register(V1, seq=2)  # seq 2 burned by the refusal
    mgr.register(V2, seq=3)
    with pytest.raises(DuplicateVersionError):
        mgr.register(V1, seq=4)  # failed mutation consumes seq 4
    with pytest.raises(SeqOrderError):
        mgr.register("2027-01-01", seq=4)
    mgr.register("2027-01-01", seq=5)


# 12. Audit shapes and rejected kind.
def test_audit_shapes_and_rejected():
    mgr = APIVersioning()
    mgr.register(V1, seq=1)
    with pytest.raises(DuplicateVersionError):
        mgr.register(V1, seq=2)
    kinds = [e["kind"] for e in mgr.audit_log()]
    assert kinds == ["versioning.version-registered", "versioning.rejected"]
    for event in mgr.audit_log():
        assert event["schema"] == AUDIT_SCHEMA
        assert event["module_version"] == API_VERSIONING_VERSION
        assert event["module"] == "api_versioning"
    with pytest.raises(APIVersioningError):
        api_versioning_audit_event("bogus.kind", 9)


# 13. latest() picks the newest date id.
def test_latest():
    mgr = APIVersioning()
    with pytest.raises(UnknownVersionError):
        mgr.latest()
    mgr.register(V2, seq=1)
    mgr.register(V1, seq=2)
    assert mgr.latest().version_id == V2


# 14. Cross-instance digest determinism.
def test_digest_determinism():
    first = APIVersioning()
    r1 = first.register(V1, seq=1, changes=("a",))
    second = APIVersioning()
    r2 = second.register(V1, seq=1, changes=("a",))
    assert r1.digest == r2.digest
    assert r1.verify()


# 15. main() self-check runs.
def test_main_self_check():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "api-versioning OK" in result.stdout
