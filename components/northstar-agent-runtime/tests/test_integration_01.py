"""Integration 01 tests."""

import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


i01 = _load("integration_01")


def test_process_tags_and_marks():
    ps = i01.ProvenanceSpotlight()
    r = ps.process("read_doc", "some data")
    assert r.tagged.provenance == "read_doc"
    assert r.nonce in r.marked
    assert "some data" in r.marked
    assert r.tool_id == "read_doc"


def test_base64_hides_plaintext():
    ps = i01.ProvenanceSpotlight(level="base64")
    r = ps.process("fetch", "secret-data")
    assert "secret-data" not in r.marked
    assert r.tagged.value == "secret-data"  # raw kept for policy


def test_policy_denies_tainted():
    ps = i01.ProvenanceSpotlight()
    r = ps.process("read_doc", "x")
    policy = {"send_email": {"allowed_sources": {"user", "internal"}}}
    assert ps.check_policy("send_email", {"body": r.tagged}, policy) is False


def test_rejects_bad_inputs():
    ps = i01.ProvenanceSpotlight()
    try:
        ps.process("", "data")
        raise AssertionError("should raise")
    except i01.IntegrationError:
        pass
    try:
        ps.process("tool", 123)
        raise AssertionError("should raise")
    except i01.IntegrationError:
        pass


def test_version_pin():
    assert i01.INTEGRATION_01_VERSION == "integration-01.v1"
    assert i01.stdlib_only() is True
