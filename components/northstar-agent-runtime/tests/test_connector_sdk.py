"""Tests for connector_sdk: 15 cases."""

import ast
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import connector_sdk
from connector_sdk import (
    AlreadyDeactivatedError,
    BadConfigError,
    BadManifestError,
    CapabilityError,
    ConnectorSDK,
    DeactivatedError,
    DuplicateConnectorError,
    DuplicateInstanceError,
    SeqOrderError,
    UnknownConnectorError,
    UnknownInstanceError,
    connector_sdk_audit_event,
)


def _sdk():
    return ConnectorSDK()


def _manifest(sdk, cid="weather", seq=1, caps=None, schema=None):
    return sdk.manifest(
        cid, "Weather", "1.0",
        ["read", "subscribe"] if caps is None else caps, seq=seq,
        config_schema=schema if schema is not None else [
            {"name": "api_key", "type": "str", "required": True},
            {"name": "timeout_s", "type": "int", "required": False},
        ],
    )


def _init(sdk, cid="weather", config=None, seq=2, instance_id=None):
    return sdk.init(cid, {"api_key": "sekret-42"} if config is None else config,
                    seq=seq, instance_id=instance_id)


def test_01_version_and_schema_pins():
    assert connector_sdk.CONNECTOR_SDK_VERSION == "connector-sdk.v1"
    assert connector_sdk.CONNECTOR_SDK_SCHEMA == "northstar.connector-sdk.v1"
    assert connector_sdk.AUDIT_SCHEMA == "audit.ndjson/1"


def test_02_stdlib_only():
    path = os.path.join(os.path.dirname(__file__), "..", "connector_sdk.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing",
        "__future__", "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_03_manifest_roundtrip_and_verify():
    sdk = _sdk()
    m = _manifest(sdk)
    assert m.connector_id == "weather"
    assert m.capabilities == ("read", "subscribe")
    assert len(m.config_schema) == 2
    assert m.verify()
    assert sdk.manifest_of("weather") == m
    assert sdk.connector_ids() == ("weather",)


def test_04_manifest_refusals():
    sdk = _sdk()
    _manifest(sdk, seq=1)
    # Duplicate id refused (seq consumed even on failure).
    try:
        _manifest(sdk, seq=1)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("rewound seq must raise SeqOrderError")
    try:
        _manifest(sdk, seq=2)
    except DuplicateConnectorError:
        pass
    else:
        raise AssertionError("duplicate connector_id must raise")
    # Unknown capability refused.
    try:
        _manifest(sdk, cid="other", seq=3, caps=["teleport"])
    except BadManifestError:
        pass
    else:
        raise AssertionError("unknown capability must raise")
    # Empty capabilities refused.
    try:
        _manifest(sdk, cid="other", seq=4, caps=[])
    except BadManifestError:
        pass
    else:
        raise AssertionError("empty capabilities must raise")
    # Bool seq refused.
    try:
        _manifest(sdk, cid="other", seq=True)
    except TypeError:
        pass
    else:
        raise AssertionError("bool seq must raise TypeError")


def test_05_init_config_validation():
    sdk = _sdk()
    _manifest(sdk, seq=1)
    inst = _init(sdk, seq=2, instance_id="i1")
    assert inst.state == "initialized"
    assert inst.verify()
    # Missing required key.
    try:
        _init(sdk, config={}, seq=3)
    except BadConfigError:
        pass
    else:
        raise AssertionError("missing required key must raise")
    # Wrong value type (bool is not int).
    try:
        _init(sdk, config={"api_key": "k", "timeout_s": True}, seq=4)
    except BadConfigError:
        pass
    else:
        raise AssertionError("bool-as-int must raise")
    # Extra key refused: closed schema.
    try:
        _init(sdk, config={"api_key": "k", "rogue": 1}, seq=5)
    except BadConfigError:
        pass
    else:
        raise AssertionError("extra config key must raise")
    # Unknown connector refused.
    try:
        sdk.init("nope", {"api_key": "k"}, seq=6)
    except UnknownConnectorError:
        pass
    else:
        raise AssertionError("unknown connector must raise")
    # Duplicate instance id refused.
    try:
        _init(sdk, seq=7, instance_id="i1")
    except DuplicateInstanceError:
        pass
    else:
        raise AssertionError("duplicate instance_id must raise")


def test_06_invoke_capability_gate_and_digest():
    sdk = _sdk()
    _manifest(sdk, seq=1)
    inst = _init(sdk, seq=2)
    inv = sdk.invoke(inst.instance_id, "read", {"city": "guangzhou"}, seq=3)
    assert inv.operation == "read"
    assert inv.payload_digest.startswith("sha256:")
    assert inv.verify()
    # Payload body is pinned, never stored raw.
    assert "guangzhou" not in str(inv.as_dict())
    # Undeclared operation refused fail-closed.
    try:
        sdk.invoke(inst.instance_id, "write", {}, seq=4)
    except CapabilityError:
        pass
    else:
        raise AssertionError("undeclared operation must raise")
    # Unknown instance refused.
    try:
        sdk.invoke("ghost", "read", {}, seq=5)
    except UnknownInstanceError:
        pass
    else:
        raise AssertionError("unknown instance must raise")


def test_07_invoke_payload_determinism():
    sdk = _sdk()
    _manifest(sdk, seq=1)
    inst = _init(sdk, seq=2)
    a = sdk.invoke(inst.instance_id, "read", {"b": 1, "a": 2}, seq=3)
    b = sdk.invoke(inst.instance_id, "read", {"a": 2, "b": 1}, seq=4)
    assert a.payload_digest == b.payload_digest
    # NaN payload refused (non-canonicalizable).
    try:
        sdk.invoke(inst.instance_id, "read", {"x": float("nan")}, seq=5)
    except ValueError:
        pass
    else:
        raise AssertionError("NaN payload must raise")


def test_08_deactivate_terminal():
    sdk = _sdk()
    _manifest(sdk, seq=1)
    inst = _init(sdk, seq=2)
    rec = sdk.deactivate(inst.instance_id, seq=3)
    assert rec.state == "deactivated"
    assert rec.verify()
    assert sdk.instance(inst.instance_id).state == "deactivated"
    # Double deactivate refused.
    try:
        sdk.deactivate(inst.instance_id, seq=4)
    except AlreadyDeactivatedError:
        pass
    else:
        raise AssertionError("double deactivate must raise")
    # Invoke after deactivate refused.
    try:
        sdk.invoke(inst.instance_id, "read", {}, seq=5)
    except DeactivatedError:
        pass
    else:
        raise AssertionError("invoke on deactivated must raise")


def test_09_config_type_vocabulary():
    sdk = _sdk()
    sdk.manifest("t", "T", "1.0", ["invoke"], seq=1, config_schema=[
        {"name": "flag", "type": "bool", "required": True},
        {"name": "ratio", "type": "float", "required": True},
        {"name": "label", "type": "str", "required": False},
    ])
    inst = sdk.init("t", {"flag": True, "ratio": 0.5}, seq=2)
    assert inst.verify()
    # int 1 is not bool.
    try:
        sdk.init("t", {"flag": 1, "ratio": 0.5}, seq=3)
    except BadConfigError:
        pass
    else:
        raise AssertionError("int-as-bool must raise")
    # int is acceptable for float.
    inst2 = sdk.init("t", {"flag": False, "ratio": 2}, seq=4,
                     instance_id="i2")
    assert inst2.verify()


def test_10_bad_config_schema_at_manifest():
    sdk = _sdk()
    # Unknown schema type refused.
    try:
        sdk.manifest("t", "T", "1.0", ["read"], seq=1,
                     config_schema=[{"name": "x", "type": "secret"}])
    except BadManifestError:
        pass
    else:
        raise AssertionError("unknown config type must raise")
    # Duplicate field name refused.
    try:
        sdk.manifest("t", "T", "1.0", ["read"], seq=2,
                     config_schema=[{"name": "x", "type": "str"},
                                    {"name": "x", "type": "str"}])
    except BadManifestError:
        pass
    else:
        raise AssertionError("duplicate field must raise")


def test_11_failed_mutation_consumes_seq():
    sdk = _sdk()
    _manifest(sdk, seq=1)
    try:
        _manifest(sdk, seq=2)  # duplicate -> DuplicateConnectorError
    except DuplicateConnectorError:
        pass
    try:
        _manifest(sdk, cid="second", seq=2)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("seq reuse after failure must raise")


def test_12_audit_shapes_and_boundary():
    sdk = _sdk()
    _manifest(sdk, seq=1)
    inst = _init(sdk, seq=2)
    sdk.invoke(inst.instance_id, "read", {"secret": "hunter2"}, seq=3)
    sdk.deactivate(inst.instance_id, seq=4)
    kinds = [e["kind"] for e in sdk.audit_log()]
    assert kinds == ["manifest-registered", "initialized", "invoked",
                     "deactivated"], kinds
    blob = str(sdk.audit_log())
    assert "hunter2" not in blob  # payload banned from audit boundary
    assert "sekret-42" not in blob  # config value banned
    for e in sdk.audit_log():
        assert e["schema"] == "audit.ndjson/1"
        assert e["event"] == "connector-sdk"
    try:
        connector_sdk_audit_event("bogus", 5)
    except ValueError:
        pass
    else:
        raise AssertionError("unknown audit kind must raise")


def test_13_views_and_snapshot():
    sdk = _sdk()
    _manifest(sdk, seq=1)
    a = _init(sdk, seq=2, instance_id="a1")
    b = _init(sdk, seq=3, instance_id="b1")
    assert sdk.instance_ids() == ("a1", "b1")
    assert sdk.instance("a1") == a
    try:
        sdk.instance("ghost")
    except UnknownInstanceError:
        pass
    else:
        raise AssertionError("unknown instance view must raise")
    snap = sdk.as_dict()
    assert snap["version"] == "connector-sdk.v1"
    assert len(snap["manifests"]) == 1 and len(snap["instances"]) == 2
    assert b.instance_id == "b1"


def test_14_main_self_check():
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        connector_sdk.main()
    assert buf.getvalue().startswith("connector-sdk OK:")


def test_15_thread_safety_smoke():
    import threading
    sdk = _sdk()
    _manifest(sdk, seq=1)
    errors = []

    def worker(n):
        try:
            inst = sdk.init("weather", {"api_key": "k"}, seq=2 + n * 3,
                            instance_id=f"w{n}")
            sdk.invoke(inst.instance_id, "read", {"n": n}, seq=3 + n * 3)
            sdk.deactivate(inst.instance_id, seq=4 + n * 3)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(sdk.instance_ids()) == 8
    assert all(sdk.instance(i).state == "deactivated"
               for i in sdk.instance_ids())
