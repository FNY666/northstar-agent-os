"""Tests for service_discovery: register/report/deregister/lookup."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import service_discovery as sd_mod
from service_discovery import (
    SERVICE_DISCOVERY_SCHEMA,
    SERVICE_DISCOVERY_VERSION,
    AuditKindError,
    BadHealthError,
    BadLookupError,
    BadServiceError,
    DeregisteredServiceError,
    DuplicateServiceError,
    SeqOrderError,
    ServiceDiscovery,
    UnknownServiceError,
    service_discovery_audit_event,
)

HERE = Path(__file__).resolve()
MOD_PATH = HERE.parent.parent / "service_discovery.py"

ALLOWED_STDLIB = {
    "hashlib",
    "re",
    "threading",
    "dataclasses",
    "typing",
    "__future__",
    "json",
    "canonical_json",
}


def test_version_pins():
    assert SERVICE_DISCOVERY_VERSION == "service-discovery.v1"
    assert SERVICE_DISCOVERY_SCHEMA == "northstar.service-discovery.v1"


def test_stdlib_only():
    tree = ast.parse(MOD_PATH.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in ALLOWED_STDLIB, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in ALLOWED_STDLIB, node.module


def test_main_self_check():
    r = subprocess.run(
        [sys.executable, str(MOD_PATH)], capture_output=True, text=True
    )
    assert r.returncode == 0
    assert "service-discovery OK" in r.stdout


def test_register_roundtrip():
    sd = ServiceDiscovery()
    rec = sd.register("web-1", "web", "10.0.0.1", 1, port=8080, tags=("v2",))
    assert rec.service_id == "web-1"
    assert rec.service_name == "web"
    assert rec.address == "10.0.0.1"
    assert rec.port == 8080
    assert rec.tags == ("v2",)
    assert rec.verify()
    assert sd.health_of("web-1") == "unknown"


def test_register_duplicate_refused():
    sd = ServiceDiscovery()
    sd.register("web-1", "web", "10.0.0.1", 1)
    with pytest.raises(DuplicateServiceError):
        sd.register("web-1", "web", "10.0.0.2", 2)
    # failed mutation consumed its seq: next seq is 3
    assert sd.stats()["last_seq"] == 2


def test_register_bad_inputs():
    sd = ServiceDiscovery()
    with pytest.raises(BadServiceError):
        sd.register("", "web", "10.0.0.1", 1)
    with pytest.raises(BadServiceError):
        sd.register("web-1", "Web!", "10.0.0.1", 2)
    with pytest.raises(BadServiceError):
        sd.register("web-1", "web", "http://x", 3)
    with pytest.raises(BadServiceError):
        sd.register("web-1", "web", "10.0.0.1", 4, port=99999)
    with pytest.raises(BadServiceError):
        sd.register("web-1", "web", "10.0.0.1", 5, port=True)


def test_report_roundtrip():
    sd = ServiceDiscovery()
    sd.register("api-1", "api", "10.0.0.2", 1)
    rep = sd.report("api-1", True, 2)
    assert rep.health == "healthy"
    assert rep.verify()
    assert sd.health_of("api-1") == "healthy"
    rep2 = sd.report("api-1", False, 3)
    assert rep2.health == "unhealthy"
    assert sd.health_of("api-1") == "unhealthy"
    with pytest.raises(BadHealthError):
        sd.report("api-1", "yes", 4)
    with pytest.raises(UnknownServiceError):
        sd.report("nope", True, 5)


def test_lookup_healthy_only():
    sd = ServiceDiscovery()
    sd.register("web-1", "web", "10.0.0.1", 1)
    sd.register("web-2", "web", "10.0.0.2", 2)
    sd.report("web-1", True, 3)
    look = sd.lookup("web", 4)
    assert look.instance_ids == ("web-1",)
    look_all = sd.lookup("web", 5, healthy_only=False)
    assert look_all.instance_ids == ("web-1", "web-2")
    assert look.verify() and look_all.verify()
    # lookup is a pure read: seq not consumed
    assert sd.stats()["last_seq"] == 3
    with pytest.raises(BadLookupError):
        sd.lookup("web", 6, healthy_only="yes")


def test_lookup_unknown_name_is_data():
    sd = ServiceDiscovery()
    look = sd.lookup("ghost", 1)
    assert look.instance_ids == ()
    assert look.verify()


def test_deregister_terminal():
    sd = ServiceDiscovery()
    sd.register("web-1", "web", "10.0.0.1", 1)
    dr = sd.deregister("web-1", 2, reason="scale-in")
    assert dr.verify()
    assert sd.lookup("web", 3, healthy_only=False).instance_ids == ()
    assert "web-1" in sd.deregistered_ids()
    with pytest.raises(DeregisteredServiceError):
        sd.deregister("web-1", 4)
    with pytest.raises(DeregisteredServiceError):
        sd.register("web-1", "web", "10.0.0.3", 5)
    with pytest.raises(DeregisteredServiceError):
        sd.report("web-1", True, 6)


def test_deregister_bad_inputs():
    sd = ServiceDiscovery()
    with pytest.raises(UnknownServiceError):
        sd.deregister("nope", 1)
    sd.register("web-1", "web", "10.0.0.1", 2)
    with pytest.raises(BadServiceError):
        sd.deregister("web-1", 3, reason="because")


def test_seq_discipline():
    sd = ServiceDiscovery()
    sd.register("web-1", "web", "10.0.0.1", 1)
    with pytest.raises(SeqOrderError):
        sd.register("web-2", "web", "10.0.0.2", 1)
    with pytest.raises(SeqOrderError):
        sd.register("web-2", "web", "10.0.0.2", True)


def test_list_services():
    sd = ServiceDiscovery()
    sd.register("web-1", "web", "10.0.0.1", 1)
    sd.register("api-1", "api", "10.0.0.2", 2)
    sd.deregister("api-1", 3)
    cat = sd.list_services(4)
    assert cat.service_names == ("web",)
    assert cat.verify()
    # pure read: seq not consumed
    assert sd.stats()["last_seq"] == 3


def test_normalization_and_views():
    sd = ServiceDiscovery()
    rec = sd.register("web-1", "WEB", "10.0.0.1 ", 1)
    assert rec.service_name == "web"
    assert rec.address == "10.0.0.1"
    assert sd.service("web-1").service_id == "web-1"
    assert sd.service_ids() == ("web-1",)
    assert len(sd.health_reports("web-1")) == 0
    d = sd.as_dict()
    assert d["schema"] == "northstar.service-discovery.v1"
    assert d["services"]["web-1"]["health"] == "unknown"


def test_audit_shapes_and_boundary():
    sd = ServiceDiscovery()
    sd.register("web-1", "web", "10.0.0.1", 1)
    log = sd.audit_log()
    kinds = [e["kind"] for e in log]
    assert "service-discovery.registered" in kinds
    for e in log:
        assert e["schema"] == "audit.ndjson/1"
        assert "address" not in e and "tags" not in e
    with pytest.raises(AuditKindError):
        service_discovery_audit_event("bogus", 1)
