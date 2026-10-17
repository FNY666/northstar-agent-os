#!/usr/bin/env python3
"""Host-owned native scan supervisor; never signs uploaded normalized records.

The profile and immutable tool roots must be operationally protected. The CLI
uses only the signed plan's scope and the two fixed native adapters. It does not
prepare source provenance or install tools. No production keys are generated.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

from native_contract import normalize_path, validated_inputs
from produce_expectation import _validated_plan_body
from trusted_common import EvidenceError, _Directory, _read_path, create_receipt, file_manifest, load_private_key, load_trust_store, parse_time, publish_directory, sha, strict_json_loads, validate_identity, verify_receipt, wire

ROOT = Path(__file__).resolve().parent
PROFILE_FIELDS = {"schema", "semgrep_root", "osv_root", "policy_dir", "database_dir", "database_updated_at", "database_ecosystems", "bwrap_path"}
MAX_TOOL_FILE_BYTES = 536870912
MAX_TOOL_TOTAL_BYTES = 3221225472


def _stream_digest(path: Path, limit: int = MAX_TOOL_FILE_BYTES) -> tuple[str, int]:
    with _Directory(path.parent) as directory:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory.fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
                raise EvidenceError("tool file is unsafe or outside budget")
            digest, count = hashlib.sha256(), 0
            first = os.read(fd, 4096)
            if first.lstrip().startswith(b"-----BEGIN") and b"PRIVATE KEY-----" in first:
                raise EvidenceError("private key cannot appear in a native tool mount")
            while first:
                count += len(first)
                if count > limit:
                    raise EvidenceError("tool file exceeds measurement budget")
                digest.update(first)
                first = os.read(fd, 1024 * 1024)
            after = os.fstat(fd)
            if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise EvidenceError("tool file changed during measurement")
            return digest.hexdigest(), count
        finally:
            os.close(fd)


def distribution_digest(root: str | Path, tool: str) -> str:
    root = Path(os.path.abspath(os.fspath(root)))
    with _Directory(root):
        pass
    entries, total = [], 0
    for directory, subdirs, files in os.walk(root, followlinks=False):
        for name in sorted(subdirs + files):
            path = Path(directory) / name
            rel = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                allowed = tool == "semgrep" and ((rel == "lib64" and target == "lib") or (rel in {"bin/python", "bin/python3", "bin/python3.12"} and path.resolve().parent == Path("/usr/bin") and path.resolve().name.startswith("python3")))
                if not allowed:
                    raise EvidenceError("tool distribution contains an unexpected symbolic link")
                if rel == "lib64":
                    entries.append({"path": rel, "link": target})
                else:
                    digest, size = _stream_digest(path.resolve())
                    entries.append({"path": rel, "link": target, "resolved_sha256": digest, "resolved_bytes": size})
                continue
            digest, size = _stream_digest(path)
            total += size
            if total > MAX_TOOL_TOTAL_BYTES or len(entries) >= 100000:
                raise EvidenceError("tool distribution exceeds total budget")
            entries.append({"path": rel, "sha256": digest, "bytes": size})
    if not entries or (tool == "osv-scanner" and {item["path"] for item in entries} != {"osv-scanner"}):
        raise EvidenceError("native distribution does not match the minimal tool root")
    return sha(wire({"schema": "northstar.native-distribution.v1", "tool": tool, "files": sorted(entries, key=lambda item: item["path"])}))


def normalizer_digest(tool: str) -> str:
    name = "semgrep_normalizer.py" if tool == "semgrep" else "osv_normalizer.py"
    files = [ROOT / name, ROOT / "native_contract.py", ROOT / "native_runner.py", ROOT / "freeze_inputs.py", ROOT / "trusted_common.py",
             ROOT / "cicd-evidence-integration/security-evidence-contract/security_evidence.py",
             ROOT / "cicd-evidence-integration/security-evidence-contract/schemas/security-scan.v1.schema.json",
             ROOT / "cicd-evidence-integration/security-evidence-contract/schemas/security-expectation.v1.schema.json"]
    return sha(wire({"schema": "northstar.native-normalizer-set.v1", "files": [{"path": p.relative_to(ROOT).as_posix(), "sha256": sha(_read_path(p, 2097152))} for p in files]}))


def load_profile(path: str | Path) -> dict:
    value = strict_json_loads(_read_path(path))
    if type(value) is not dict or set(value) != PROFILE_FIELDS or value["schema"] != "northstar.native-scan-profile.v1":
        raise EvidenceError("native profile must be a closed host-owned object")
    for name in PROFILE_FIELDS - {"schema", "database_updated_at", "database_ecosystems"}:
        if type(value[name]) is not str or not value[name].startswith("/") or "\x00" in value[name]:
            raise EvidenceError("native profile path must be an absolute host path")
    parse_time(value["database_updated_at"])
    ecosystems = value["database_ecosystems"]
    if type(ecosystems) is not list or not ecosystems or len(ecosystems) > 32 or len(set(ecosystems)) != len(ecosystems) or any(type(x) is not str or not x.replace("-", "").isalnum() for x in ecosystems):
        raise EvidenceError("native database ecosystems are invalid")
    return value


def profile_pins(profile: dict) -> dict:
    """Measure protected artifacts BEFORE a planner signs a template.

    This is not an allowlist/approval service: the resulting pins must first be
    reviewed against the intended deployment toolchain, never auto-approved from
    a candidate profile by a caller with the plan key.
    """
    policy_dir = Path(profile["policy_dir"])
    rules = _read_path(policy_dir / "semgrep.yaml")
    osv_config = _read_path(policy_dir / "osv.toml")
    severity = strict_json_loads(_read_path(policy_dir / "severity-map.json"))
    if type(severity) is not dict or not severity or any(type(k) is not str or not k or v not in {"critical", "high", "medium", "low", "info"} for k, v in severity.items()):
        raise EvidenceError("host severity map is invalid")
    bwrap_digest, _ = _stream_digest(Path(profile["bwrap_path"]))
    database_files = []
    for ecosystem in sorted(profile["database_ecosystems"]):
        relative = "osv-scanner/" + ecosystem + "/all.zip"
        digest, size = _stream_digest(Path(profile["database_dir"]) / relative)
        database_files.append({"path": relative, "sha256": digest, "bytes": size})
    db_manifest = {"schema": "northstar.osv-database-view.v1", "updated_at": profile["database_updated_at"], "ecosystems": sorted(profile["database_ecosystems"]), "files": database_files}
    database = {"manifest_sha256": sha(wire(db_manifest)), "updated_at": profile["database_updated_at"], "ecosystems": sorted(profile["database_ecosystems"])}
    tools = {}
    for tool, version, policy_raw in (("semgrep", "1.181.0", rules), ("osv-scanner", "2.7.0", osv_config)):
        config = {"schema": "northstar.native-host-config.v1", "tool": tool, "policy_sha256": sha(policy_raw), "bwrap_sha256": bwrap_digest, "runner_sha256": sha(_read_path(ROOT / "native_runner.py")), "severity_map": severity if tool == "semgrep" else None}
        tools[tool] = {"version": version, "distribution_sha256": distribution_digest(profile["semgrep_root"] if tool == "semgrep" else profile["osv_root"], tool), "normalizer_sha256": normalizer_digest(tool), "config_sha256": sha(wire(config)), "rules_sha256": sha(rules) if tool == "semgrep" else None, "database_manifest_sha256": database["manifest_sha256"] if tool == "osv-scanner" else None}
    return {"tools": tools, "database": database, "severity_map": severity}


def read_inputs(root: str | Path, expected: list[dict]) -> dict[str, bytes]:
    result = {}
    total = 0
    for item in expected:
        rel = normalize_path(item["path"])
        if rel != item["path"]:
            raise EvidenceError("signed input path is not canonical")
        raw = _read_path(Path(root) / rel, 1000000)
        total += len(raw)
        if total > 67108864 or sha(raw) != item["sha256"]:
            raise EvidenceError("frozen native input bytes differ from signed scope")
        result[rel] = raw
    return result


def input_manifest_sha256(inputs: dict[str, bytes]) -> str:
    return sha(wire({"schema": "northstar.native-input-view.v1", "files": [{"path": p, "sha256": sha(raw), "bytes": len(raw)} for p, raw in sorted(inputs.items())]}))


def _copy_view(root: Path, inputs: dict[str, bytes]) -> None:
    root.mkdir(mode=0o700)
    for relative, raw in inputs.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw)
        path.chmod(0o444)
    for directory, _, _ in os.walk(root, topdown=False):
        Path(directory).chmod(0o555)


def capture_scans(plan_path, profile_path, semgrep_input_dir, osv_input_dir, output_dir,
                  trust_store, expected_identity, signing_key, *, timeout_seconds=120) -> dict:
    from tempfile import TemporaryDirectory
    from freeze_inputs import validate_requirements
    from native_runner import run_native
    from semgrep_normalizer import normalize_semgrep
    from osv_normalizer import normalize_osv

    validate_identity(expected_identity)
    plan_raw = _read_path(plan_path, 4194304)
    plan = verify_receipt(plan_raw, trust_store, expected_kind="scan-plan", expected_identity=expected_identity)
    body, _context_with_zero_pins = _validated_plan_body(plan["body"], expected_identity)
    template = body["expectation_template"]
    profile = load_profile(profile_path)
    pins = profile_pins(profile)
    views = {}
    for tool, source in (("semgrep", semgrep_input_dir), ("osv-scanner", osv_input_dir)):
        config = template["tools"][tool]
        if not config["required"]:
            raise EvidenceError("first native supervisor profile requires both scans; not-applicable needs separate reviewed host logic")
        for key, observed in pins["tools"][tool].items():
            if config[key] != observed:
                raise EvidenceError("signed native tool/profile pin mismatch")
        views[tool] = read_inputs(source, config["expected_inputs"])
        validated_inputs(template, tool, views[tool])
        if config["scan_view_manifest_sha256"] != input_manifest_sha256(views[tool]):
            raise EvidenceError("signed scan view manifest differs from actual frozen scope")
    if set(views["osv-scanner"]) != {"requirements.txt"} or profile["database_ecosystems"] != ["PyPI"]:
        raise EvidenceError("first live dependency profile requires exactly root requirements.txt and the PyPI database")
    for name, raw in views["osv-scanner"].items():
        if not name.endswith("requirements.txt"):
            raise EvidenceError("first live native dependency profile only supports restricted requirements.txt")
        validate_requirements(raw)
    files, executions = {}, {}
    with TemporaryDirectory(prefix="northstar-native-host-") as temp:
        private = Path(temp)
        # Native processes never mount the original source/plan/profile/key paths.
        for tool in ("semgrep", "osv-scanner"):
            view = private / tool
            _copy_view(view, views[tool])
            run = run_native(tool, tool_root=Path(profile["semgrep_root"] if tool == "semgrep" else profile["osv_root"]), input_dir=view,
                             policy_dir=Path(profile["policy_dir"]), database_dir=Path(profile["database_dir"]) if tool == "osv-scanner" else None,
                             bwrap_path=Path(profile["bwrap_path"]), timeout_seconds=timeout_seconds)
            started = parse_time(run["execution"]["started_at"])
            if parse_time(plan["issued_at"]) > started:
                raise EvidenceError("native scan began before signed plan issuance")
            args = {"template": template, "execution": run["execution"], "isolation": run["isolation"], "input_bytes": views[tool], "stderr": run["stderr"]}
            record = normalize_semgrep(run["stdout"], severity_map=pins["severity_map"], **args) if tool == "semgrep" else normalize_osv(run["stdout"], database=pins["database"], **args)
            prefix = "semgrep" if tool == "semgrep" else "osv"
            files[template["tools"][tool]["evidence_file"]] = wire(record)
            files[prefix + ".stdout.json"] = run["stdout"]
            files[prefix + ".stderr.txt"] = run["stderr"]
            executions[tool] = {"execution": record["execution"], "coverage": record["coverage"], "findings_count": len(record["findings"]), "isolation": record["isolation"]}
    if profile_pins(profile) != pins:
        raise EvidenceError("native tool/config/database changed while scanning")
    # Only the supervisor signs its own captured output, never an imported JSON.
    capture_raw = create_receipt("scan-capture", expected_identity, {"schema": "northstar.scan-capture.v1", "plan_sha256": sha(plan_raw), "files": file_manifest(files)}, signing_key, trust_store)
    output = Path(output_dir)
    publish_directory(output, {**files, "capture.dsse.json": capture_raw})
    return {"schema": "northstar.native-scan-supervisor-result.v1", "exit_code": 0, "capture_sha256": sha(capture_raw), "output_dir": str(output), "scans": executions,
            "limitations": ["This authenticates host captures, not complete source-to-binary provenance or unknown-vulnerability absence.", "Restricted exact requirements cover declared packages only, not inferred transitive dependencies.", "Production admission still requires approved immutable profile/tool roots and deployment resource controls."]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run two fixed native read-only scanners and sign only their host-captured outputs.")
    for name in ("plan", "profile", "semgrep-input-dir", "osv-input-dir", "output", "trust-store", "identity", "signing-key-file"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        profile = load_profile(args.profile)
        key_path = Path(args.signing_key_file).resolve(strict=True)
        # A key may not be in ANY native-readable root, even if the caller supplied it there.
        for field in ("semgrep_root", "osv_root", "policy_dir", "database_dir"):
            if key_path.is_relative_to(Path(profile[field]).resolve(strict=True)):
                raise EvidenceError("signing key cannot be placed in a native-readable root")
        result = capture_scans(args.plan, args.profile, args.semgrep_input_dir, args.osv_input_dir, args.output,
                               load_trust_store(args.trust_store), strict_json_loads(_read_path(args.identity)), load_private_key(key_path))
    except Exception as error:
        result = {"schema": "northstar.native-scan-supervisor-result.v1", "exit_code": 2, "error": type(error).__name__}
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
