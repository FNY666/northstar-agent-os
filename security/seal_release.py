#!/usr/bin/env python3
"""Create an immutable, signed release-seal from trusted scan and build receipts.

This module deliberately does not run scanners, normalizers, project code, or a
build.  A deployment still needs a physically separated scan supervisor and
build supervisor: their receipts authenticate the captured bytes, not those
properties by themselves.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent
_INTEGRATION_DIRECTORY = _ROOT / "cicd-evidence-integration"
_CONTRACT_DIRECTORY = _ROOT / "cicd-evidence-integration" / "security-evidence-contract"
if str(_INTEGRATION_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(_INTEGRATION_DIRECTORY))
if str(_CONTRACT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(_CONTRACT_DIRECTORY))

from security_evidence import evaluate_bundle  # noqa: E402
from verify_release_files import verify_release_files  # noqa: E402
from trusted_common import (  # noqa: E402
    EvidenceError,
    _Directory,
    _context_semantics,
    _read_path,
    _validators,
    clock,
    create_receipt,
    file_manifest,
    load_private_key,
    load_trust_store,
    parse_time,
    publish_directory,
    read_manifest_files,
    sha,
    strict_json_loads,
    validate_identity,
    verify_receipt,
    wire,
)

try:  # packaging is part of the fixed local Python environment used by the contract.
    from packaging.utils import canonicalize_name, parse_wheel_filename
    from packaging.version import Version
except ImportError as error:  # pragma: no cover - deterministic deployment failure
    raise RuntimeError("packaging is required for release wheel filename validation") from error

MAX_RECEIPT_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
_HEX64 = re.compile(r"[a-f0-9]{64}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!]{0,127}\Z")

PLAN_NAME = "plan.dsse.json"
CAPTURE_NAME = "capture.dsse.json"
BUILD_CAPTURE_NAME = "build-capture.dsse.json"
EXPECTATION_NAME = "host-expectation.json"
EXPECTATION_RECEIPT_NAME = "expectation.dsse.json"
# The producer gate is retained under the contract's distinct canonical name.
# security-gate.json is the fresh seal-time evaluation, while this file is
# necessary to verify the expectation receipt's immutable historical gate pin.
PRODUCER_GATE_NAME = "producer-gate.json"
GATE_NAME = "security-gate.json"
BINDING_NAME = "release-binding.json"
SEAL_NAME = "release-seal.dsse.json"
_CONTROL_NAMES = {
    PLAN_NAME,
    CAPTURE_NAME,
    BUILD_CAPTURE_NAME,
    EXPECTATION_NAME,
    EXPECTATION_RECEIPT_NAME,
    PRODUCER_GATE_NAME,
    GATE_NAME,
    BINDING_NAME,
    SEAL_NAME,
}


def _bad(message: str) -> None:
    raise EvidenceError(message)


def _trust(value: Any) -> dict[str, Any]:
    """Accept an already-loaded store for APIs, or securely load an external one."""
    if isinstance(value, (str, os.PathLike)):
        value = load_trust_store(value)
    if type(value) is not dict:
        _bad("trust store must be an externally loaded dictionary")
    return value


def _hex(value: Any, field: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        _bad(f"{field} must be lower-case sha256")
    return value


def _name(value: Any, field: str = "file name") -> str:
    if type(value) is not str or _SAFE_NAME.fullmatch(value) is None:
        _bad(f"{field} is not a safe single file name")
    return value


def _body(payload: Any, fields: set[str], schema: str) -> dict[str, Any]:
    if type(payload) is not dict or set(payload) != {"schema", "kind", "identity", "issued_at", "expires_at", "body"}:
        _bad("verified receipt payload has an unexpected structure")
    body = payload.get("body")
    if type(body) is not dict or set(body) != fields or body.get("schema") != schema:
        _bad("receipt body has an unexpected structure")
    return body


def _manifest(value: Any, *, field: str = "files", forbid: set[str] | None = None) -> list[dict[str, Any]]:
    """Validate the closed common manifest shape independently of its producer."""
    if type(value) is not list or not 1 <= len(value) <= 128:
        _bad(f"{field} must be a non-empty bounded manifest")
    total = 0
    names: list[str] = []
    result: list[dict[str, Any]] = []
    forbidden = forbid or set()
    for item in value:
        if type(item) is not dict or set(item) != {"name", "sha256", "bytes"}:
            _bad(f"{field} item is not closed")
        name = _name(item.get("name"), field)
        digest = _hex(item.get("sha256"), field)
        size = item.get("bytes")
        if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
            _bad(f"{field} item byte count is invalid")
        if name in forbidden:
            _bad(f"{field} conflicts with a reserved output name")
        names.append(name)
        total += size
        if total > MAX_TOTAL_BYTES:
            _bad(f"{field} exceeds total byte budget")
        result.append({"name": name, "sha256": digest, "bytes": size})
    if len(set(names)) != len(names) or names != sorted(names):
        _bad(f"{field} must have unique sorted file names")
    return result


def _manifest_map(manifest: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item["name"]: item for item in manifest}


def _same_manifest(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> bool:
    return left == right


def _expect_hash(value: Any, raw: bytes, field: str) -> None:
    if _hex(value, field) != sha(raw):
        _bad(f"{field} pin mismatch")


def _pass_gate(raw: bytes, expected_run_id: str, expectation_raw: bytes | None = None) -> dict[str, Any]:
    gate = strict_json_loads(raw)
    if (
        not {"schema", "run_id", "decision", "exit_code", "eligible_for_delivery", "evidence_valid"}.issubset(gate)
        or gate.get("schema") != "northstar.security-gate.v1"
        or gate.get("run_id") != expected_run_id
        or gate.get("decision") != "pass"
        or type(gate.get("exit_code")) is not int
        or gate.get("exit_code") != 0
        or gate.get("eligible_for_delivery") is not True
        or gate.get("evidence_valid") is not True
    ):
        _bad("security gate is not an eligible pass result")
    if expectation_raw is not None:
        context = strict_json_loads(expectation_raw)
        policy = context.get("policy")
        if type(policy) is not dict or gate.get("host_expectation_sha256") != sha(expectation_raw):
            _bad("gate does not bind the exact host expectation bytes")
        if gate.get("subject") != context.get("subject") or gate.get("policy") != {key: policy.get(key) for key in ("id", "sha256")}:
            _bad("gate subject or policy differs from authenticated expectation")
    return gate


def _template_context(plan_body: dict[str, Any], capture_files: dict[str, bytes] | None = None) -> dict[str, Any]:
    """Validate a plan template and optionally fill only authenticated evidence hashes."""
    template = plan_body["expectation_template"]
    if type(template) is not dict or template.get("schema") != "northstar.security-expectation.v1":
        _bad("scan plan template is invalid")
    if type(template.get("tools")) is not dict or set(template["tools"]) != {"semgrep", "osv-scanner"}:
        _bad("scan plan must define exactly the two trusted tools")
    context = copy.deepcopy(template)
    for tool_name in ("semgrep", "osv-scanner"):
        tool = context["tools"][tool_name]
        if type(tool) is not dict or "evidence_sha256" in tool:
            _bad("signed template must omit every evidence hash")
        evidence_file = _name(tool.get("evidence_file"), "template evidence file")
        if evidence_file in _CONTROL_NAMES:
            _bad("template evidence file conflicts with a control file")
        if capture_files is None:
            tool["evidence_sha256"] = "0" * 64
        else:
            raw = capture_files.get(evidence_file)
            if raw is None:
                _bad("captured evidence does not include the planned evidence file")
            tool["evidence_sha256"] = sha(raw)

    try:
        _scan_validator, expectation_validator = _validators()
        if any(expectation_validator.iter_errors(context)) or _context_semantics(context):
            _bad("scan plan template does not satisfy the legacy expectation contract")
    except EvidenceError:
        raise
    except Exception as error:
        raise EvidenceError("unable to validate signed plan template") from error
    return context


def _release_plan(plan_payload: dict[str, Any], expected_identity: dict[str, Any]) -> dict[str, Any]:
    fields = {"schema", "expectation_template", "release_components", "release_version"}
    body = _body(plan_payload, fields, "northstar.scan-plan.v1")
    identity = plan_payload["identity"]
    if identity != expected_identity or body["expectation_template"].get("run_id") != identity["run_id"]:
        _bad("signed scan plan is not bound to the current identity")
    _template_context(body)
    # 复用同一预签计划规范，六组件与保留名约束在签发/消费阶段保持一致。
    # source_commit 为最终候选；subject.start_commit 为补丁起点，不能强制相等。
    from produce_expectation import _validated_plan_body
    _validated_plan_body(body, expected_identity)

    components = body["release_components"]
    if type(components) is not list or not 1 <= len(components) <= 64:
        _bad("release component list is invalid")
    canonical: list[str] = []
    for component in components:
        _name(component, "release component")
        canonical.append(canonicalize_name(component))
    if len(set(canonical)) != len(canonical):
        _bad("release components are duplicated after package normalization")
    version = body["release_version"]
    if type(version) is not str or _SAFE_VERSION.fullmatch(version) is None or "-" in version:
        _bad("release version is not safe")
    try:
        if str(Version(version)) != version:
            _bad("release version is not canonical")
    except EvidenceError:
        raise
    except Exception as error:
        raise EvidenceError("release version is invalid") from error
    return body


def _capture_body(payload: dict[str, Any], plan_raw: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    body = _body(payload, {"schema", "plan_sha256", "files"}, "northstar.scan-capture.v1")
    _expect_hash(body["plan_sha256"], plan_raw, "capture plan_sha256")
    files = _manifest(body["files"], field="capture files", forbid=_CONTROL_NAMES)
    return body, files


def _expectation_body(payload: dict[str, Any], *, plan_raw: bytes, capture_raw: bytes, expectation_raw: bytes, gate_raw: bytes) -> dict[str, Any]:
    body = _body(
        payload,
        {"schema", "plan_sha256", "capture_sha256", "expectation_sha256", "gate_sha256"},
        "northstar.expectation-receipt.v1",
    )
    _expect_hash(body["plan_sha256"], plan_raw, "expectation plan_sha256")
    _expect_hash(body["capture_sha256"], capture_raw, "expectation capture_sha256")
    _expect_hash(body["expectation_sha256"], expectation_raw, "expectation expectation_sha256")
    _expect_hash(body["gate_sha256"], gate_raw, "expectation gate_sha256")
    return body


def _build_body(payload: dict[str, Any], plan_raw: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    body = _body(payload, {"schema", "plan_sha256", "files"}, "northstar.build-capture.v1")
    _expect_hash(body["plan_sha256"], plan_raw, "build capture plan_sha256")
    files = _manifest(body["files"], field="build wheel files", forbid=_CONTROL_NAMES)
    if any(not item["name"].endswith(".whl") for item in files):
        _bad("build capture may authenticate only wheel files")
    return body, files


def _wheel_components(plan_body: dict[str, Any], wheels: list[dict[str, Any]]) -> None:
    expected = {canonicalize_name(item) for item in plan_body["release_components"]}
    if len(wheels) != len(expected):
        _bad("the signed plan requires exactly one wheel per component")
    observed: set[str] = set()
    expected_version = plan_body["release_version"]
    for descriptor in wheels:
        try:
            distribution, version, _build, _tags = parse_wheel_filename(descriptor["name"])
        except Exception as error:
            raise EvidenceError("wheel filename is not valid") from error
        component = canonicalize_name(str(distribution))
        if component not in expected or component in observed:
            _bad("wheel component is absent from plan or duplicated")
        if str(version) != expected_version:
            _bad("wheel version differs from signed release plan")
        observed.add(component)
    if observed != expected:
        _bad("a planned component wheel is missing")


def _fresh_gate(capture_files: dict[str, bytes], expectation_raw: bytes, now_value: Any) -> tuple[dict[str, Any], bytes]:
    """Run the legacy evaluator against a private copy of the exact authenticated bytes."""
    with tempfile.TemporaryDirectory(prefix="northstar-seal-evidence-") as temporary:
        root = Path(temporary)
        inputs = dict(capture_files)
        if EXPECTATION_NAME in inputs:
            _bad("capture manifest conflicts with host expectation control file")
        inputs[EXPECTATION_NAME] = expectation_raw
        for name, raw in inputs.items():
            _name(name)
            fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
            try:
                offset = 0
                while offset < len(raw):
                    offset += os.write(fd, raw[offset:])
                os.fsync(fd)
            finally:
                os.close(fd)
        result = evaluate_bundle(root, root / EXPECTATION_NAME, now=now_value)
    if (
        result.get("schema") != "northstar.security-gate.v1"
        or result.get("decision") != "pass"
        or result.get("exit_code") != 0
        or result.get("eligible_for_delivery") is not True
        or result.get("evidence_valid") is not True
    ):
        _bad("legacy evidence evaluator did not return pass")
    return result, wire(result)


def _capture_time_order(plan_payload: dict[str, Any], capture_payload: dict[str, Any], context: dict[str, Any], capture_files: dict[str, bytes]) -> None:
    """Enforce the plan-before-scan and capture-after-scan ordering that receipts bind."""
    plan_time = parse_time(plan_payload["issued_at"])
    capture_time = parse_time(capture_payload["issued_at"])
    for tool_name in ("semgrep", "osv-scanner"):
        if not context["tools"][tool_name]["required"]:
            continue
        evidence_name = context["tools"][tool_name]["evidence_file"]
        try:
            record = strict_json_loads(capture_files[evidence_name])
            execution = record["execution"]
            started = parse_time(execution["started_at"])
            finished = parse_time(execution["finished_at"])
        except Exception as error:
            raise EvidenceError("required capture timing cannot be validated") from error
        if plan_time > started:
            _bad("scan began before the signed plan was issued")
        if capture_time + timedelta(seconds=60) < finished:
            _bad("scan capture was signed too far before scanning completed")


def _capture_record_names(context: dict[str, Any], capture_files: dict[str, bytes]) -> None:
    """A capture has exactly the two normalized records and declared stdout/stderr blobs."""
    expected: set[str] = set()
    for tool_name in ("semgrep", "osv-scanner"):
        record_name = context["tools"][tool_name]["evidence_file"]
        if record_name in expected or record_name not in capture_files:
            _bad("capture lacks a distinct planned normalized record")
        expected.add(record_name)
        try:
            record = strict_json_loads(capture_files[record_name])
            artifacts = record["artifacts"]
            if type(artifacts) is not dict or set(artifacts) != {"stdout", "stderr"}:
                _bad("normalized record lacks a closed artifacts object")
            for stream in ("stdout", "stderr"):
                artifact = artifacts[stream]
                if artifact is None:
                    continue
                if type(artifact) is not dict:
                    _bad("normalized record has malformed artifact declaration")
                name = _name(artifact.get("name"), "captured artifact")
                if name in _CONTROL_NAMES:
                    _bad("captured artifact conflicts with a control file")
                expected.add(name)
        except EvidenceError:
            raise
        except Exception as error:
            raise EvidenceError("cannot determine capture record files") from error
    if set(capture_files) != expected:
        _bad("capture contains omitted or undeclared files")


def _binding(raw: bytes, expected_gate: bytes, identity: dict[str, Any], wheels: list[dict[str, Any]]) -> dict[str, Any]:
    binding = strict_json_loads(raw)
    if type(binding) is not dict or set(binding) != {"schema", "run_id", "source_commit", "security_gate_sha256", "files"}:
        _bad("release binding is not closed")
    if binding.get("schema") != "northstar.release-binding.v1":
        _bad("release binding schema mismatch")
    if binding.get("run_id") != identity["run_id"] or binding.get("source_commit") != identity["source_commit"]:
        _bad("release binding identity mismatch")
    _expect_hash(binding.get("security_gate_sha256"), expected_gate, "binding security_gate_sha256")
    files = _manifest(binding.get("files"), field="binding files", forbid=_CONTROL_NAMES)
    if not _same_manifest(files, wheels):
        _bad("release binding wheels differ from authenticated build capture")
    return binding


def _validate_release_body(payload: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    fields = {
        "schema", "plan_sha256", "capture_sha256", "build_capture_sha256", "expectation_receipt_sha256",
        "expectation_sha256", "security_gate_sha256", "binding_sha256", "files",
    }
    body = _body(payload, fields, "northstar.release-seal.v1")
    for field in fields - {"schema", "files"}:
        _hex(body[field], f"release seal {field}")
    files = _manifest(body["files"], field="release seal files", forbid={SEAL_NAME})
    required = {
        PLAN_NAME, CAPTURE_NAME, BUILD_CAPTURE_NAME, EXPECTATION_NAME,
        EXPECTATION_RECEIPT_NAME, PRODUCER_GATE_NAME, GATE_NAME, BINDING_NAME,
    }
    names = {item["name"] for item in files}
    if not required.issubset(names):
        _bad("release seal is missing a required signed control file")
    return body, files


def _read_produced(produced_dir: str | Path, trust_store: dict[str, Any], expected_identity: dict[str, Any], now_value: Any) -> tuple[dict[str, bytes], dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    """Read an Agent-A directory exactly once logically, then confirm its full file set."""
    root = Path(produced_dir)
    controls: dict[str, bytes] = {}
    for name in (PLAN_NAME, CAPTURE_NAME, EXPECTATION_NAME, GATE_NAME, EXPECTATION_RECEIPT_NAME):
        controls[name] = _read_path(root / name, MAX_RECEIPT_BYTES)

    plan_payload = verify_receipt(controls[PLAN_NAME], trust_store, expected_kind="scan-plan", expected_identity=expected_identity, now=now_value)
    plan_body = _release_plan(plan_payload, expected_identity)
    capture_payload = verify_receipt(controls[CAPTURE_NAME], trust_store, expected_kind="scan-capture", expected_identity=expected_identity, now=now_value)
    _capture, capture_manifest = _capture_body(capture_payload, controls[PLAN_NAME])
    expectation_payload = verify_receipt(controls[EXPECTATION_RECEIPT_NAME], trust_store, expected_kind="expectation", expected_identity=expected_identity, now=now_value)
    _expectation_body(
        expectation_payload,
        plan_raw=controls[PLAN_NAME],
        capture_raw=controls[CAPTURE_NAME],
        expectation_raw=controls[EXPECTATION_NAME],
        gate_raw=controls[GATE_NAME],
    )
    _pass_gate(controls[GATE_NAME], expected_identity["run_id"], controls[EXPECTATION_NAME])

    control_manifest = file_manifest(controls)
    complete_manifest = _manifest(sorted(capture_manifest + control_manifest, key=lambda item: item["name"]), field="produced directory files")
    files = read_manifest_files(root, complete_manifest, max_total=MAX_TOTAL_BYTES)
    if any(files[name] != raw for name, raw in controls.items()):
        _bad("produced control file changed during validation")

    context = _template_context(plan_body, files)
    if files[EXPECTATION_NAME] != wire(context):
        _bad("host expectation was not deterministically derived from signed plan and capture bytes")
    captured = {item["name"]: files[item["name"]] for item in capture_manifest}
    _capture_record_names(context, captured)
    _capture_time_order(plan_payload, capture_payload, context, captured)
    _fresh_gate(captured, files[EXPECTATION_NAME], now_value)
    return files, plan_payload, capture_payload, expectation_payload, capture_manifest


def _seal_release(
    produced_dir: str | Path,
    build_capture_path: str | Path,
    dist_dir: str | Path,
    output_dir: str | Path,
    trust_store: dict[str, Any] | str | Path,
    expected_identity: dict[str, Any],
    signing_key: Any,
    *,
    now: Any = None,
) -> dict[str, Any]:
    """Verify and seal one complete release; raise EvidenceError without publishing on failure."""
    validate_identity(expected_identity)
    if type(expected_identity) is not dict:
        _bad("expected identity must be a closed dictionary")
    store = _trust(trust_store)
    now_value = clock(now)

    produced, plan_payload, _capture_payload, expectation_payload, capture_manifest = _read_produced(
        produced_dir, store, expected_identity, now_value
    )
    plan_raw = produced[PLAN_NAME]
    plan_body = _release_plan(plan_payload, expected_identity)

    build_raw = _read_path(build_capture_path, MAX_RECEIPT_BYTES)
    build_payload = verify_receipt(build_raw, store, expected_kind="build-capture", expected_identity=expected_identity, now=now_value)
    _build, wheel_manifest = _build_body(build_payload, plan_raw)
    _wheel_components(plan_body, wheel_manifest)
    wheel_bytes = read_manifest_files(dist_dir, wheel_manifest, max_total=MAX_TOTAL_BYTES)
    if set(wheel_bytes) & set(produced):
        _bad("build wheel names collide with authenticated produced evidence files")

    # Re-run the legacy checker on immutable copies.  This is intentionally not
    # a comparison with a stale producer gate.
    capture_bytes = {item["name"]: produced[item["name"]] for item in capture_manifest}
    fresh_result, fresh_gate_raw = _fresh_gate(capture_bytes, produced[EXPECTATION_NAME], now_value)

    binding_value = {
        "schema": "northstar.release-binding.v1",
        "run_id": expected_identity["run_id"],
        "source_commit": expected_identity["source_commit"],
        "security_gate_sha256": sha(fresh_gate_raw),
        "files": wheel_manifest,
    }
    binding_raw = wire(binding_value)

    # The preserved checker must process the same immutable wheel bytes and the
    # newly generated gate/binding bytes, never a path in an untrusted tree.
    with tempfile.TemporaryDirectory(prefix="northstar-seal-release-") as temporary:
        temp = Path(temporary)
        temp_dist = temp / "dist"
        temp_dist.mkdir(mode=0o700)
        for name, raw in wheel_bytes.items():
            (temp_dist / name).write_bytes(raw)
            os.chmod(temp_dist / name, 0o400)
        binding_path = temp / BINDING_NAME
        gate_path = temp / GATE_NAME
        binding_path.write_bytes(binding_raw)
        gate_path.write_bytes(fresh_gate_raw)
        os.chmod(binding_path, 0o400)
        os.chmod(gate_path, 0o400)
        old_check = verify_release_files(
            temp_dist,
            binding_path,
            gate_path,
            expected_binding_sha256=sha(binding_raw),
            expected_source_commit=expected_identity["source_commit"],
            expected_run_id=expected_identity["run_id"],
            expected_gate_sha256=sha(fresh_gate_raw),
        )
    if old_check.get("eligible_for_publish") is not True or old_check.get("exit_code") != 0:
        _bad("legacy release file checker rejected the authenticated bytes")

    output_files: dict[str, bytes] = {}
    for name, raw in produced.items():
        if name == GATE_NAME:
            output_files[PRODUCER_GATE_NAME] = raw
        else:
            output_files[name] = raw
    output_files[BUILD_CAPTURE_NAME] = build_raw
    output_files.update(wheel_bytes)
    output_files[GATE_NAME] = fresh_gate_raw
    output_files[BINDING_NAME] = binding_raw
    if SEAL_NAME in output_files:
        _bad("release output file name collision")

    release_body = {
        "schema": "northstar.release-seal.v1",
        "plan_sha256": sha(plan_raw),
        "capture_sha256": sha(produced[CAPTURE_NAME]),
        "build_capture_sha256": sha(build_raw),
        "expectation_receipt_sha256": sha(produced[EXPECTATION_RECEIPT_NAME]),
        "expectation_sha256": sha(produced[EXPECTATION_NAME]),
        "security_gate_sha256": sha(fresh_gate_raw),
        "binding_sha256": sha(binding_raw),
        "files": file_manifest(output_files),
    }
    seal_raw = create_receipt("release-seal", expected_identity, release_body, signing_key, store, now=now_value)
    output_files[SEAL_NAME] = seal_raw
    publish_directory(output_dir, output_files)
    return {
        "schema": "northstar.seal-release-result.v1",
        "exit_code": 0,
        "eligible_for_publish": True,
        "output_dir": str(output_dir),
        "release_seal_sha256": sha(seal_raw),
        "binding_sha256": sha(binding_raw),
        "security_gate_sha256": sha(fresh_gate_raw),
        "decision": fresh_result["decision"],
    }


def seal_release(
    produced_dir: str | Path,
    build_capture_path: str | Path,
    dist_dir: str | Path,
    output_dir: str | Path,
    trust_store: dict[str, Any] | str | Path,
    expected_identity: dict[str, Any],
    signing_key: Any,
    *,
    now: Any = None,
) -> dict[str, Any]:
    """Fail closed as EvidenceError for every untrusted input or filesystem fault."""
    try:
        return _seal_release(
            produced_dir,
            build_capture_path,
            dist_dir,
            output_dir,
            trust_store,
            expected_identity,
            signing_key,
            now=now,
        )
    except EvidenceError:
        raise
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise EvidenceError(f"cannot safely seal release: {type(error).__name__}") from error


def _identity_file(path: str | Path) -> dict[str, Any]:
    value = strict_json_loads(_read_path(path, MAX_RECEIPT_BYTES))
    validate_identity(value)
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify trusted evidence/build receipts and atomically seal a release.")
    parser.add_argument("--produced-dir", required=True)
    parser.add_argument("--build-capture", required=True)
    parser.add_argument("--dist-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--trust-store", required=True, help="externally deployed trust-store JSON")
    parser.add_argument("--identity", required=True, help="current identity JSON from trusted CI control plane")
    parser.add_argument("--signing-key-file", required=True)
    args = parser.parse_args(argv)
    try:
        answer = seal_release(
            args.produced_dir,
            args.build_capture,
            args.dist_dir,
            args.output,
            load_trust_store(args.trust_store),
            _identity_file(args.identity),
            load_private_key(args.signing_key_file),
        )
    except Exception as error:
        print(json.dumps({"schema": "northstar.seal-release-result.v1", "exit_code": 2, "error": type(error).__name__}, separators=(",", ":")))
        return 2
    print(json.dumps(answer, ensure_ascii=True, separators=(",", ":"), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
