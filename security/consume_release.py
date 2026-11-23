#!/usr/bin/env python3
"""Read-only verification for a Northstar release-seal package.

The trust store and current CI identity are supplied out of band.  No keyring,
pin, gate, or identity found in the sealed directory becomes a trust root.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from seal_release import (
    BINDING_NAME,
    BUILD_CAPTURE_NAME,
    CAPTURE_NAME,
    EXPECTATION_NAME,
    EXPECTATION_RECEIPT_NAME,
    GATE_NAME,
    MAX_FILE_BYTES,
    MAX_RECEIPT_BYTES,
    MAX_TOTAL_BYTES,
    PLAN_NAME,
    PRODUCER_GATE_NAME,
    SEAL_NAME,
    _binding,
    _build_body,
    _capture_body,
    _capture_record_names,
    _capture_time_order,
    _expect_hash,
    _expectation_body,
    _fresh_gate,
    _manifest_map,
    _pass_gate,
    _read_produced,
    _release_plan,
    _same_manifest,
    _template_context,
    _trust,
    _validate_release_body,
    _wheel_components,
)
from trusted_common import (
    EvidenceError,
    _Directory,
    _read_path,
    clock,
    load_trust_store,
    read_manifest_files,
    sha,
    strict_json_loads,
    validate_identity,
    verify_receipt,
)
from verify_release_files import verify_release_files


def _failure() -> dict[str, Any]:
    """Keep malformed package details out of the normal consumer result."""
    return {
        "schema": "northstar.consume-release-result.v1",
        "eligible_for_publish": False,
        "exit_code": 2,
        "reason_codes": ["RELEASE_SEAL_VALIDATION_FAILED"],
        "limitations": [
            "校验不会重新运行扫描器、normalizer、项目代码或构建。",
            "签名和字节绑定不能单独证明物理隔离、源码到制品真实性或不存在未知安全问题。",
        ],
    }


def _read_package_after_seal(root: str | Path, manifest: list[dict[str, Any]], seal_raw: bytes) -> dict[str, bytes]:
    """Read exactly manifest files plus the separately-listed seal with no-follow FDs."""
    expected = _manifest_map(manifest)
    if SEAL_NAME in expected:
        raise EvidenceError("release seal must not include itself in its file manifest")
    wanted = set(expected) | {SEAL_NAME}
    total = sum(item["bytes"] for item in manifest)
    if total > MAX_TOTAL_BYTES:
        raise EvidenceError("release package exceeds byte budget")
    values: dict[str, bytes] = {}
    with _Directory(root) as directory:
        before = set(os.listdir(directory.fd))
        if before != wanted:
            raise EvidenceError("sealed directory has missing or extra files")
        # The previously verified seal is re-read in this same exact-tree pass;
        # a substitution race cannot cause its old signature to bless new data.
        current_seal = directory.read(SEAL_NAME, MAX_RECEIPT_BYTES)
        if current_seal != seal_raw:
            raise EvidenceError("release seal changed during validation")
        for name, descriptor in expected.items():
            raw = directory.read(name, descriptor["bytes"])
            if len(raw) != descriptor["bytes"] or sha(raw) != descriptor["sha256"]:
                raise EvidenceError("sealed manifest byte mismatch")
            values[name] = raw
        if set(os.listdir(directory.fd)) != before:
            raise EvidenceError("sealed directory changed during validation")
    return values


def _verify_old_release_checker(wheels: dict[str, bytes], binding_raw: bytes, gate_raw: bytes, identity: dict[str, Any]) -> None:
    """Invoke the preserved release checker against only immutable copied bytes."""
    with tempfile.TemporaryDirectory(prefix="northstar-consume-release-") as temporary:
        root = Path(temporary)
        dist = root / "dist"
        dist.mkdir(mode=0o700)
        for name, raw in wheels.items():
            (dist / name).write_bytes(raw)
            os.chmod(dist / name, 0o400)
        binding_path = root / BINDING_NAME
        gate_path = root / GATE_NAME
        binding_path.write_bytes(binding_raw)
        gate_path.write_bytes(gate_raw)
        os.chmod(binding_path, 0o400)
        os.chmod(gate_path, 0o400)
        result = verify_release_files(
            dist,
            binding_path,
            gate_path,
            expected_binding_sha256=sha(binding_raw),
            expected_source_commit=identity["source_commit"],
            expected_run_id=identity["run_id"],
            expected_gate_sha256=sha(gate_raw),
        )
    if result.get("eligible_for_publish") is not True or result.get("exit_code") != 0:
        raise EvidenceError("preserved release checker rejected sealed bytes")


def _consume_verified(sealed_dir: str | Path, store: dict[str, Any], identity: dict[str, Any], now_value: Any) -> dict[str, Any]:
    root = Path(sealed_dir)
    # This is intentionally the only package file read before release-seal
    # verification.  The verifier validates DSSE before interpreting its body.
    seal_raw = _read_path(root / SEAL_NAME, MAX_RECEIPT_BYTES)
    seal_payload = verify_receipt(seal_raw, store, expected_kind="release-seal", expected_identity=identity, now=now_value)
    seal_body, manifest = _validate_release_body(seal_payload)

    files = _read_package_after_seal(root, manifest, seal_raw)
    for field, name in (
        ("plan_sha256", PLAN_NAME),
        ("capture_sha256", CAPTURE_NAME),
        ("build_capture_sha256", BUILD_CAPTURE_NAME),
        ("expectation_receipt_sha256", EXPECTATION_RECEIPT_NAME),
        ("expectation_sha256", EXPECTATION_NAME),
        ("security_gate_sha256", GATE_NAME),
        ("binding_sha256", BINDING_NAME),
    ):
        _expect_hash(seal_body[field], files[name], f"release seal {field}")

    plan_payload = verify_receipt(files[PLAN_NAME], store, expected_kind="scan-plan", expected_identity=identity, now=now_value)
    plan_body = _release_plan(plan_payload, identity)
    capture_payload = verify_receipt(files[CAPTURE_NAME], store, expected_kind="scan-capture", expected_identity=identity, now=now_value)
    _capture, capture_manifest = _capture_body(capture_payload, files[PLAN_NAME])
    expectation_payload = verify_receipt(files[EXPECTATION_RECEIPT_NAME], store, expected_kind="expectation", expected_identity=identity, now=now_value)
    _expectation_body(
        expectation_payload,
        plan_raw=files[PLAN_NAME],
        capture_raw=files[CAPTURE_NAME],
        expectation_raw=files[EXPECTATION_NAME],
        gate_raw=files[PRODUCER_GATE_NAME],
    )
    _pass_gate(files[PRODUCER_GATE_NAME], identity["run_id"], files[EXPECTATION_NAME])

    build_payload = verify_receipt(files[BUILD_CAPTURE_NAME], store, expected_kind="build-capture", expected_identity=identity, now=now_value)
    _build, wheel_manifest = _build_body(build_payload, files[PLAN_NAME])
    _wheel_components(plan_body, wheel_manifest)

    sealed_manifest = _manifest_map(manifest)
    for descriptor in capture_manifest + wheel_manifest:
        listed = sealed_manifest.get(descriptor["name"])
        if listed != descriptor:
            raise EvidenceError("upstream capture/build file is absent or differs from the release manifest")
    # A .whl cannot be smuggled as an arbitrary signed auxiliary release file.
    all_wheels = {name for name in files if name.endswith(".whl")}
    if all_wheels != {item["name"] for item in wheel_manifest}:
        raise EvidenceError("sealed wheel set differs from signed build capture")

    context = _template_context(plan_body, files)
    from trusted_common import wire  # imported here to keep trust primitives explicit at the call site
    if files[EXPECTATION_NAME] != wire(context):
        raise EvidenceError("host expectation differs from deterministic plan/capture derivation")
    capture_values = {item["name"]: files[item["name"]] for item in capture_manifest}
    _capture_record_names(context, capture_values)
    _capture_time_order(plan_payload, capture_payload, context, capture_values)

    # Validate the seal-time gate and bind it to the new binding.  Then run the
    # old evaluator again using the current trusted clock, including freshness;
    # equality to the historical gate bytes is neither expected nor safe.
    _pass_gate(files[GATE_NAME], identity["run_id"], files[EXPECTATION_NAME])
    _binding(files[BINDING_NAME], files[GATE_NAME], identity, wheel_manifest)
    fresh_result, _fresh_raw = _fresh_gate(capture_values, files[EXPECTATION_NAME], now_value)
    if fresh_result.get("decision") != "pass":  # defensive; _fresh_gate already enforces this
        raise EvidenceError("current evidence re-evaluation did not pass")

    wheels = {item["name"]: files[item["name"]] for item in wheel_manifest}
    _verify_old_release_checker(wheels, files[BINDING_NAME], files[GATE_NAME], identity)
    return {
        "schema": "northstar.consume-release-result.v1",
        "eligible_for_publish": True,
        "exit_code": 0,
        "reason_codes": [],
        "release_seal_sha256": sha(seal_raw),
        "binding_sha256": sha(files[BINDING_NAME]),
        "security_gate_sha256": sha(files[GATE_NAME]),
        "limitations": [
            "通过只表示外部信任根所授权的签名图、当前身份、字节完整性和重新检查的门禁均满足合同。",
            "未实现扫描器、normalizer、物理隔离或源码到wheel来源的独立证明；这些仍依赖受信部署的监督者。",
        ],
    }


def consume_release(
    sealed_dir: str | Path,
    trust_store: dict[str, Any] | str | Path,
    expected_identity: dict[str, Any],
    *,
    now: Any = None,
) -> dict[str, Any]:
    """Fail closed and never write the sealed input directory."""
    try:
        validate_identity(expected_identity)
        if type(expected_identity) is not dict:
            raise EvidenceError("expected identity must be a dictionary")
        return _consume_verified(sealed_dir, _trust(trust_store), expected_identity, clock(now))
    except Exception:
        return _failure()


def _identity_file(path: str | Path) -> dict[str, Any]:
    value = strict_json_loads(_read_path(path, MAX_RECEIPT_BYTES))
    validate_identity(value)
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only verification of a signed Northstar sealed release.")
    parser.add_argument("--sealed-dir", required=True)
    parser.add_argument("--trust-store", required=True, help="externally deployed trust-store JSON")
    parser.add_argument("--identity", required=True, help="current identity JSON from trusted CI control plane")
    args = parser.parse_args(argv)
    try:
        answer = consume_release(args.sealed_dir, load_trust_store(args.trust_store), _identity_file(args.identity))
    except Exception:
        answer = _failure()
    print(json.dumps(answer, ensure_ascii=True, separators=(",", ":"), allow_nan=False))
    return int(answer["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
