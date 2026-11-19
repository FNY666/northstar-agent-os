"""Fail-closed verification of host-reported sandbox evidence.

The host adapter owns enforcement; this module only validates the evidence it
returns against a previously generated :class:`SandboxPlan`. A successful
process exit is never treated as proof that isolation was active.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from tools.deterministic_kernel import SandboxPlan

SCHEMA = "northstar.sandbox-evidence.v1"
_ALLOWED_BACKENDS = {"process", "bwrap", "oci", "gvisor", "microvm"}


class EvidenceError(ValueError):
    """Evidence is missing, inconsistent, or weaker than the requested plan."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EvidenceError("evidence is not canonical JSON") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _required_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise EvidenceError(f"{field} must be a positive integer")
    return value


def _required_count(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceError(f"{field} must be a non-negative integer")
    return value


@dataclass(frozen=True)
class SandboxEvidence:
    plan_digest: str
    backend: str
    runtime_digest: str
    rootless: bool
    workspace_readonly: bool
    network_mode: str
    seccomp_loaded: bool
    seccomp_profile_digest: str
    cgroup_enforced: bool
    cgroup_path: str
    effective_memory_max_bytes: int
    effective_pids_max: int
    effective_cpu_max_percent: int
    descendant_pids: int
    evidence_digest: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SandboxEvidence":
        if not isinstance(raw, Mapping) or raw.get("schema") != SCHEMA:
            raise EvidenceError("invalid sandbox evidence schema")
        required = {
            "plan_digest", "backend", "runtime_digest", "rootless",
            "workspace_readonly", "network_mode", "seccomp_loaded",
            "seccomp_profile_digest", "cgroup_enforced", "cgroup_path",
            "effective_memory_max_bytes", "effective_pids_max",
            "effective_cpu_max_percent", "descendant_pids", "evidence_digest",
        }
        if set(raw) != required | {"schema"}:
            raise EvidenceError("sandbox evidence has unknown or missing fields")
        body = {key: raw[key] for key in required if key != "evidence_digest"}
        body = {"schema": SCHEMA, **body}
        if raw["evidence_digest"] != _digest(body):
            raise EvidenceError("sandbox evidence digest mismatch")
        for field in ("plan_digest", "runtime_digest", "seccomp_profile_digest", "cgroup_path"):
            if not isinstance(raw[field], str) or not raw[field] or "\x00" in raw[field] or "\n" in raw[field]:
                raise EvidenceError(f"invalid evidence field: {field}")
        if raw["backend"] not in _ALLOWED_BACKENDS:
            raise EvidenceError("unsupported sandbox backend")
        if raw["network_mode"] not in {"none", "unverified"}:
            raise EvidenceError("network_mode must be none or unverified")
        if not isinstance(raw["rootless"], bool) or not isinstance(raw["workspace_readonly"], bool):
            raise EvidenceError("rootless and workspace_readonly must be booleans")
        if not isinstance(raw["seccomp_loaded"], bool) or not isinstance(raw["cgroup_enforced"], bool):
            raise EvidenceError("seccomp_loaded and cgroup_enforced must be booleans")
        for field in ("effective_memory_max_bytes", "effective_pids_max", "effective_cpu_max_percent"):
            _required_int(raw[field], field)
        _required_count(raw["descendant_pids"], "descendant_pids")
        return cls(**{key: raw[key] for key in required})

    def as_dict(self) -> dict[str, Any]:
        body = {
            "schema": SCHEMA,
            "plan_digest": self.plan_digest,
            "backend": self.backend,
            "runtime_digest": self.runtime_digest,
            "rootless": self.rootless,
            "workspace_readonly": self.workspace_readonly,
            "network_mode": self.network_mode,
            "seccomp_loaded": self.seccomp_loaded,
            "seccomp_profile_digest": self.seccomp_profile_digest,
            "cgroup_enforced": self.cgroup_enforced,
            "cgroup_path": self.cgroup_path,
            "effective_memory_max_bytes": self.effective_memory_max_bytes,
            "effective_pids_max": self.effective_pids_max,
            "effective_cpu_max_percent": self.effective_cpu_max_percent,
            "descendant_pids": self.descendant_pids,
        }
        return {**body, "evidence_digest": _digest(body)}


def verify_evidence(plan: SandboxPlan, raw: Mapping[str, Any], *, require_os_isolation: bool = False) -> SandboxEvidence:
    """Verify host evidence is at least as restrictive as ``plan``."""
    if not isinstance(plan, SandboxPlan):
        raise EvidenceError("plan must be a SandboxPlan")
    evidence = SandboxEvidence.from_dict(raw)
    if evidence.plan_digest != plan.digest:
        raise EvidenceError("sandbox evidence does not match plan digest")
    if not evidence.rootless or not evidence.workspace_readonly:
        raise EvidenceError("sandbox is not rootless and read-only")
    if evidence.network_mode != plan.data["network"]:
        raise EvidenceError("effective network policy does not match plan")
    if evidence.backend == "process":
        raise EvidenceError("process backend is not an OS sandbox; install/use bwrap or a stronger backend")
    if plan.data["seccomp"] == "required" and not evidence.seccomp_loaded:
        raise EvidenceError("required seccomp profile was not loaded")
    if not evidence.cgroup_enforced:
        raise EvidenceError("cgroup v2 resource enforcement is not evidenced")
    if evidence.descendant_pids != 0:
        raise EvidenceError("sandbox has surviving descendant processes")
    if evidence.effective_memory_max_bytes > plan.data["memory_max_bytes"]:
        raise EvidenceError("effective memory limit is weaker than plan")
    if evidence.effective_pids_max > plan.data["pids_max"]:
        raise EvidenceError("effective pids limit is weaker than plan")
    if evidence.effective_cpu_max_percent > plan.data["cpu_max_percent"]:
        raise EvidenceError("effective CPU limit is weaker than plan")
    if require_os_isolation and evidence.backend == "microvm":
        # microVM is accepted as OS isolation; this branch documents the
        # explicit policy check and keeps unsupported future backends closed.
        pass
    if require_os_isolation and evidence.backend not in {"bwrap", "oci", "gvisor", "microvm"}:
        raise EvidenceError("requested OS isolation has no approved backend")
    return evidence


__all__ = ["EvidenceError", "SandboxEvidence", "SCHEMA", "verify_evidence"]
