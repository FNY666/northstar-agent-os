#!/usr/bin/env python3
"""Produce a host expectation from independently signed scan-plan and scan-capture.

This module never runs a scanner and never derives policy, scope, or tool pins
from candidate evidence.  The signed plan is the sole source for that context;
the signed capture supplies only the final bytes pinned into it.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
LEGACY = ROOT / "cicd-evidence-integration" / "security-evidence-contract"
if str(LEGACY) not in sys.path:
    sys.path.insert(0, str(LEGACY))

from security_evidence import evaluate_bundle  # noqa: E402
from trusted_common import (  # noqa: E402
    EvidenceError,
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


TOOLS = ("semgrep", "osv-scanner")
RELEASE_COMPONENTS = (
    "northstar_run_contract",
    "northstar_run_evidence",
    "northstar_host",
    "northstar_durable_run",
    "northstar_agent_interop",
    "northstar_agent_runtime",
)
ZERO_SHA256 = "0" * 64
# ``trusted_common.verify_receipt`` permits a 3 MiB DSSE envelope.  Read the
# same bounded maximum so a valid maximum-size authenticated receipt is not
# rejected before its signature can be checked.
MAX_RECEIPT_BYTES = 3 * 1024 * 1024
FIXED_OUTPUT_NAMES = frozenset(
    {
        "plan.dsse.json",
        "capture.dsse.json",
        "host-expectation.json",
        "security-gate.json",
        "expectation.dsse.json",
        "producer-gate.json",
        "build-capture.dsse.json",
        "release-binding.json",
        "release-seal.dsse.json",
    }
)
TEMPLATE_KEYS = frozenset({"schema", "run_id", "subject", "policy", "tools"})
PLAN_BODY_KEYS = frozenset({"schema", "expectation_template", "release_components", "release_version"})
CAPTURE_BODY_KEYS = frozenset({"schema", "plan_sha256", "files"})
TOOL_TEMPLATE_KEYS = frozenset(
    {
        "required",
        "not_applicable_reason",
        "evidence_file",
        "version",
        "distribution_sha256",
        "normalizer_sha256",
        "config_sha256",
        "rules_sha256",
        "database_manifest_sha256",
        "scan_view_manifest_sha256",
        "isolation_backend",
        "expected_inputs",
    }
)
VERSION = re.compile(r"[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*\Z")


def _fail(message: str) -> None:
    raise EvidenceError(message)


def _closed_mapping(value: Any, required: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != required:
        _fail(f"{label} must contain exactly the required fields")
    return value


def _schema_errors(validator: Any, value: Any) -> list[str]:
    """Bound legacy-schema diagnostics without relying on an unexported helper."""
    errors: list[str] = []
    for error in validator.iter_errors(value):
        location = "/".join(str(part) for part in error.absolute_path) or "$"
        errors.append(f"{location[:180]} violates {error.validator}")
        if len(errors) == 40:
            errors.append("schema error limit reached")
            break
    return errors


def _validated_plan_body(body: Any, identity: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate a closed signed plan and return (body, context-with-zero-pins)."""
    plan = _closed_mapping(body, PLAN_BODY_KEYS, "scan-plan body")
    if plan["schema"] != "northstar.scan-plan.v1":
        _fail("scan-plan body schema is unsupported")
    if plan["release_components"] != list(RELEASE_COMPONENTS):
        _fail("scan-plan release_components do not match the closed reference component set")
    if not isinstance(plan["release_version"], str) or not VERSION.fullmatch(plan["release_version"]):
        _fail("scan-plan release_version is not safe ASCII without a hyphen")

    template = _closed_mapping(plan["expectation_template"], TEMPLATE_KEYS, "expectation_template")
    if template["schema"] != "northstar.security-expectation.v1":
        _fail("expectation_template schema is unsupported")
    if template["run_id"] != identity["run_id"]:
        _fail("scan-plan expectation run_id does not bind the current identity")
    subject = template["subject"]
    if not isinstance(subject, dict):
        _fail("scan-plan subject must be a contracted object")
    # source_commit 是当前最终候选身份；start_commit 是补丁起始提交。
    # 两者可不同。最终身份由已验签plan的identity绑定，不能强行覆盖起始提交。
    tools = template["tools"]
    if not isinstance(tools, dict) or set(tools) != set(TOOLS):
        _fail("expectation_template must contain exactly the two contracted tools")

    context = copy.deepcopy(template)
    evidence_names: set[str] = set()
    for tool in TOOLS:
        item = context["tools"][tool]
        if not isinstance(item, dict) or set(item) != TOOL_TEMPLATE_KEYS:
            _fail(f"scan-plan template for {tool} must exclude evidence_sha256 and contain exact fields")
        # A plan may not pre-authorize a real evidence hash for a candidate to replace.
        if "evidence_sha256" in item:
            _fail(f"scan-plan template for {tool} contains forbidden evidence_sha256")
        name = item["evidence_file"]
        if not isinstance(name, str) or name in FIXED_OUTPUT_NAMES:
            _fail("captured evidence filename conflicts with a producer-controlled output")
        evidence_names.add(name)
        item["evidence_sha256"] = ZERO_SHA256
    if len(evidence_names) != len(TOOLS):
        _fail("the two captured normalized records must have distinct filenames")

    _, expectation_validator = _validators()
    errors = _schema_errors(expectation_validator, context)
    if errors:
        _fail("scan-plan expectation template violates the legacy expectation schema")
    errors = _context_semantics(context)
    if errors:
        _fail("scan-plan expectation template violates expectation semantics")
    return plan, context


def _validated_capture_body(body: Any, plan_raw: bytes) -> dict[str, Any]:
    capture = _closed_mapping(body, CAPTURE_BODY_KEYS, "scan-capture body")
    if capture["schema"] != "northstar.scan-capture.v1":
        _fail("scan-capture body schema is unsupported")
    if capture["plan_sha256"] != sha(plan_raw):
        _fail("scan-capture is not pinned to these exact signed plan bytes")
    if not isinstance(capture["files"], list):
        _fail("scan-capture files must be a manifest list")
    return capture


def _write_private_file(root: Path, name: str, payload: bytes) -> None:
    """Write a verified byte string to a newly created private scratch file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(root / name, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                _fail("could not freeze captured bytes")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _freeze_capture(root: Path, files: dict[str, bytes]) -> None:
    for name, payload in files.items():
        _write_private_file(root, name, payload)


def _capture_record_names(context: dict[str, Any], files: dict[str, bytes]) -> tuple[set[str], dict[str, dict[str, Any]]]:
    """Determine the complete capture file set from plan filenames and raw record artifacts.

    This deliberately does not use records to populate any host context.  It only
    rejects a capture manifest that is not exactly two records plus their declared
    raw stdout/stderr blobs.
    """
    expected: set[str] = set()
    records: dict[str, dict[str, Any]] = {}
    for tool in TOOLS:
        record_name = context["tools"][tool]["evidence_file"]
        raw = files.get(record_name)
        if raw is None:
            _fail(f"scan-capture omits the normalized {tool} record")
        try:
            record = strict_json_loads(raw)
        except EvidenceError:
            raise
        if not isinstance(record, dict):  # strict_json_loads currently guarantees this; keep fail closed.
            _fail("captured normalized record is not an object")
        artifacts = record.get("artifacts")
        if not isinstance(artifacts, dict) or set(artifacts) != {"stdout", "stderr"}:
            _fail("captured normalized record lacks a closed artifacts object")
        expected.add(record_name)
        for stream in ("stdout", "stderr"):
            artifact = artifacts[stream]
            if artifact is None:
                continue
            if not isinstance(artifact, dict) or not isinstance(artifact.get("name"), str):
                _fail("captured raw artifact declaration is malformed")
            expected.add(artifact["name"])
        records[tool] = record
    if expected & FIXED_OUTPUT_NAMES:
        _fail("scan-capture attempts to occupy a producer-controlled output filename")
    return expected, records


def _check_receipt_timing(plan_payload: dict[str, Any], capture_payload: dict[str, Any], records: dict[str, dict[str, Any]]) -> None:
    """Ensure planning predates scans and capture is not prematurely issued."""
    try:
        plan_issued = parse_time(plan_payload["issued_at"])
        capture_issued = parse_time(capture_payload["issued_at"])
    except (KeyError, TypeError, EvidenceError) as error:
        raise EvidenceError("verified receipt lacks a valid issuance time") from error

    starts: list[datetime] = []
    finishes: list[datetime] = []
    for tool in TOOLS:
        execution = records[tool].get("execution")
        if not isinstance(execution, dict):
            _fail("captured normalized record lacks an execution object")
        started = execution.get("started_at")
        finished = execution.get("finished_at")
        try:
            if started is not None:
                starts.append(parse_time(started))
            if finished is not None:
                finishes.append(parse_time(finished))
        except EvidenceError as error:
            raise EvidenceError("captured normalized record has an invalid execution timestamp") from error
    if starts and plan_issued > min(starts):
        _fail("scan-plan was issued after a captured scan had already begun")
    # Clock granularity across the scan supervisor and receipt issuer may differ by up to 60 s.
    if finishes and capture_issued + timedelta(seconds=60) < max(finishes):
        _fail("scan-capture was issued materially before a captured scan finished")


def _frozen_capture_evaluation(
    context: dict[str, Any],
    captured: dict[str, bytes],
    plan_payload: dict[str, Any],
    capture_payload: dict[str, Any],
    now: datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Freeze first, then validate the exact authenticated capture bytes.

    The initial manifest read authenticates the source directory.  All parsing of
    normalized records, temporal checks, and legacy evaluation occurs only after
    those bytes have been copied to this private temporary directory and read
    back against the same canonical manifest.
    """
    with tempfile.TemporaryDirectory(prefix="northstar-expectation-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        _freeze_capture(root, captured)
        frozen = read_manifest_files(root, file_manifest(captured))
        if frozen != captured:
            _fail("frozen capture bytes differ from the authenticated source bytes")
        expected_names, records = _capture_record_names(context, frozen)
        if set(frozen) != expected_names:
            _fail("scan-capture must contain exactly normalized records and their raw artifacts")
        _check_receipt_timing(plan_payload, capture_payload, records)

        # Only the already authenticated plan template is copied.  The sole
        # candidate-derived values inserted are final byte hashes at its
        # preselected evidence filenames.
        expectation = copy.deepcopy(context)
        for tool in TOOLS:
            name = expectation["tools"][tool]["evidence_file"]
            expectation["tools"][tool]["evidence_sha256"] = sha(frozen[name])
        expectation_raw = wire(expectation)
        _write_private_file(root, "host-expectation.json", expectation_raw)
        gate = evaluate_bundle(root, root / "host-expectation.json", now=now)
    if not isinstance(gate, dict):
        _fail("legacy evidence validator returned a non-object result")
    return expectation, gate


def produce_expectation(
    plan_path: str | Path,
    capture_path: str | Path,
    evidence_dir: str | Path,
    output_dir: str | Path,
    trust_store: dict[str, Any],
    expected_identity: dict[str, Any],
    signing_key: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify a signed scan plan/capture and atomically publish a signed expectation.

    ``expected_identity`` is an external trusted CI-control-plane value.  It is
    never synthesized from either receipt.  Invalid evidence raises
    :class:`EvidenceError` and publishes no output; valid ``review`` and ``block``
    diagnostics are sealed so their gate semantics remain inspectable.
    """
    try:
        validate_identity(expected_identity)
        current_time = clock(now)
        plan_raw = _read_path(plan_path, MAX_RECEIPT_BYTES)
        plan_payload = verify_receipt(
            plan_raw,
            trust_store,
            expected_kind="scan-plan",
            expected_identity=expected_identity,
            now=current_time,
        )
        _, context = _validated_plan_body(plan_payload.get("body"), expected_identity)

        # Authenticate the capture before consulting its manifest or reading a candidate file.
        capture_raw = _read_path(capture_path, MAX_RECEIPT_BYTES)
        capture_payload = verify_receipt(
            capture_raw,
            trust_store,
            expected_kind="scan-capture",
            expected_identity=expected_identity,
            now=current_time,
        )
        capture_body = _validated_capture_body(capture_payload.get("body"), plan_raw)

        captured = read_manifest_files(evidence_dir, capture_body["files"])
        # Require the canonical manifest generated from the actual bytes; this also rejects
        # duplicate/unsorted descriptions rather than accepting an ambiguous signed list.
        if file_manifest(captured) != capture_body["files"]:
            _fail("scan-capture manifest is not the canonical complete file manifest")
        expectation, gate = _frozen_capture_evaluation(
            context, captured, plan_payload, capture_payload, current_time
        )
        expectation_raw = wire(expectation)
        if gate.get("evidence_valid") is not True or gate.get("decision") == "invalid":
            _fail("captured evidence is invalid and must not receive an expectation receipt")
        gate_raw = wire(gate)

        expectation_receipt = create_receipt(
            "expectation",
            expected_identity,
            {
                "schema": "northstar.expectation-receipt.v1",
                "plan_sha256": sha(plan_raw),
                "capture_sha256": sha(capture_raw),
                "expectation_sha256": sha(expectation_raw),
                "gate_sha256": sha(gate_raw),
            },
            signing_key,
            trust_store,
            now=current_time,
        )
        published = dict(captured)
        published.update(
            {
                "plan.dsse.json": plan_raw,
                "capture.dsse.json": capture_raw,
                "host-expectation.json": expectation_raw,
                "security-gate.json": gate_raw,
                "expectation.dsse.json": expectation_receipt,
            }
        )
        publish_directory(output_dir, published)
        return {
            "exit_code": gate["exit_code"],
            "expectation_sha256": sha(expectation_raw),
            "gate_sha256": sha(gate_raw),
            "receipt_sha256": sha(expectation_receipt),
            "output_dir": os.path.abspath(os.fspath(output_dir)),
            "decision": gate["decision"],
        }
    except EvidenceError:
        raise
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise EvidenceError(f"cannot safely produce expectation: {type(error).__name__}") from error


def _load_identity(path: str | Path) -> dict[str, Any]:
    identity = strict_json_loads(_read_path(path, MAX_RECEIPT_BYTES))
    validate_identity(identity)
    return identity


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify trusted scan records and publish a sealed security expectation.")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--capture", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--trust-store", required=True)
    parser.add_argument("--identity", required=True, help="trusted CI-control-plane identity JSON")
    parser.add_argument("--signing-key-file", required=True)
    args = parser.parse_args(argv)
    try:
        result = produce_expectation(
            args.plan,
            args.capture,
            args.evidence_dir,
            args.output,
            load_trust_store(args.trust_store),
            _load_identity(args.identity),
            load_private_key(args.signing_key_file),
        )
    except EvidenceError as error:
        # stdout remains machine-readable; avoid traceback or sensitive key material.
        result = {"exit_code": 2, "decision": "invalid", "error": str(error)}
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
