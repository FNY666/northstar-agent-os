"""Adapter from ``tools.os_sandbox`` results to the evidence contract.

The adapter never upgrades a weak backend. It records process-backend facts so
operators can explain a refusal, but ``verify_evidence`` still rejects that
backend as a non-OS sandbox. Runtime facts that cannot be proven from a
``SandboxResult`` must be supplied explicitly by the trusted host.
"""
from __future__ import annotations

from typing import Any, Mapping

from tools.deterministic_kernel import SandboxPlan
from tools.os_sandbox import SandboxRequest, SandboxResult
from tools.sandbox_evidence import EvidenceError, SandboxEvidence


class SandboxEvidenceAdapterError(EvidenceError):
    """The os_sandbox result cannot be converted without inventing facts."""


_REQUIRED_FACTS = frozenset({
    "runtime_digest",
    "seccomp_profile_digest",
    "rootless",
    "workspace_readonly",
    "cgroup_path",
    "descendant_pids",
})


def evidence_from_sandbox_result(
    plan: SandboxPlan,
    request: SandboxRequest,
    result: SandboxResult,
    *,
    runtime_facts: Mapping[str, Any],
) -> dict[str, Any]:
    """Convert one real ``run_sandboxed`` result into raw evidence JSON.

    ``runtime_facts`` is deliberately explicit because a result object cannot
    prove uid/user-namespace state, a read-only mount, profile identity,
    cgroup ownership, or descendant cleanup by itself. Missing facts are an
    adapter error rather than guessed defaults.
    """
    if not isinstance(plan, SandboxPlan):
        raise SandboxEvidenceAdapterError("plan must be a SandboxPlan")
    if not isinstance(request, SandboxRequest):
        raise SandboxEvidenceAdapterError("request must be a SandboxRequest")
    if not isinstance(result, SandboxResult):
        raise SandboxEvidenceAdapterError("result must be a SandboxResult")
    if not isinstance(runtime_facts, Mapping):
        raise SandboxEvidenceAdapterError("runtime_facts must be a mapping")
    missing = sorted(_REQUIRED_FACTS - set(runtime_facts))
    if missing:
        raise SandboxEvidenceAdapterError(
            "runtime facts are incomplete; refusing to invent: " + ", ".join(missing)
        )
    if result.argv != request.argv:
        raise SandboxEvidenceAdapterError("sandbox result argv does not match request argv")
    if result.backend not in {"process", "bwrap"}:
        raise SandboxEvidenceAdapterError(f"unsupported os_sandbox backend: {result.backend!r}")
    if result.backend == "bwrap" and result.isolation != "os":
        raise SandboxEvidenceAdapterError("bwrap result did not report OS isolation")
    if result.backend == "process" and result.isolation != "process":
        raise SandboxEvidenceAdapterError("process result has an inconsistent isolation label")

    detail = result.detail.lower()
    seccomp_requested = (request.seccomp or "auto").strip().lower() != "off"
    seccomp_loaded = seccomp_requested and (
        "seccomp" in detail
        and ("prctl" in detail or "bpf" in detail or "deny" in detail or "denies" in detail)
    )
    network_none = (
        "network namespace unshared" in detail
        or "seccomp denies network socket creation" in detail
        or "seccomp denies network socket creation and escape syscalls" in detail
    )
    cgroup_enforced = (
        request.aggregate_resource_scope == "systemd"
        and not result.aggregate_setup_failed
        and not result.aggregate_cleanup_failed
    )
    descendant_pids = runtime_facts["descendant_pids"]
    if isinstance(descendant_pids, bool) or not isinstance(descendant_pids, int) or descendant_pids < 0:
        raise SandboxEvidenceAdapterError("descendant_pids must be a non-negative int")

    evidence = SandboxEvidence(
        plan_digest=plan.digest,
        backend=result.backend,
        runtime_digest=runtime_facts["runtime_digest"],
        rootless=runtime_facts["rootless"],
        workspace_readonly=runtime_facts["workspace_readonly"],
        network_mode="none" if network_none else "unverified",
        seccomp_loaded=seccomp_loaded,
        seccomp_profile_digest=runtime_facts["seccomp_profile_digest"],
        cgroup_enforced=cgroup_enforced,
        cgroup_path=runtime_facts["cgroup_path"],
        effective_memory_max_bytes=request.memory_limit_bytes,
        effective_pids_max=request.max_tasks,
        effective_cpu_max_percent=100,
        descendant_pids=descendant_pids,
        evidence_digest="",
    )
    raw = evidence.as_dict()
    # Validate the adapter's own output before handing it to the kernel. This
    # catches malformed host facts while still preserving a process result as
    # an explicit, later-verifiable refusal.
    SandboxEvidence.from_dict(raw)
    return raw


__all__ = ["SandboxEvidenceAdapterError", "evidence_from_sandbox_result"]
