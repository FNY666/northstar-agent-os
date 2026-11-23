"""Deny-monotonicity check for the governance bench.

NVIDIA OpenShell + Sentry (Sept 2026) ships a formal policy prover with a
"boundary check": a candidate policy must be provably contained in the
authorized boundary, so policy edits cannot silently open holes. The
lightweight equivalent for Northstar's gate: pin the current gate's deny
set (every probe the gate denies, with its machine-readable deny code)
and fail the bench whenever a gate change *loses* a denial. Denials may
only be added, never silently dropped -- deny-monotonicity.

Design notes:

- The corpus is small and fixed on purpose. It is not an adversarial
  benchmark; it is a *canary set* covering one probe per distinct deny
  path in the gate (disallowed list, argument policy, composition rule,
  authority ceiling, fail-closed mutating default). If a gate refactor
  accidentally weakens any path, at least one canary stops denying and
  the bench goes red.
- Deny identity is ``(probe_id, deny_code)``, not just probe_id. A probe
  that still denies but under a *different* code is a semantic change
  worth flagging: the old ``(probe, code)`` pair is reported as loosened
  and the new pair is reported as added.
- The baseline is a plain JSON file pinned next to this module
  (``deny_monotonicity_baseline.json``). Regenerating it is a deliberate,
  reviewed act -- ``regenerate_baseline()`` -- never something the bench
  does on its own. A missing baseline fails closed: without a pin there
  is nothing to be monotone against.
- ``gate_fn`` receives the raw probe dict and returns a
  ``PermissionDecision``. The bench wires the real gate; unit tests may
  wire fakes.

Attribution: boundary-check concept from NVIDIA OpenShell + Sentry
(Sept 2026); canary-set shape is original Northstar work against
Northstar's gate API.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

DENY_MONOTONICITY_VERSION = "deny-monotonicity.v1"

BASELINE_FILENAME = "deny_monotonicity_baseline.json"

#: One canary per distinct deny path. ``config`` selects the engine
#: fixture built by ``build_gate_fn()``; ``setup`` is a sequence of
#: (tool, kind, payload) calls evaluated on the same fresh engine before
#: the probe call (used by the composition canary).
DENY_CORPUS: tuple[dict[str, Any], ...] = (
    {
        "probe": "disallowed-tool",
        "tool": "BankTransfer",
        "kind": "mutating",
        "payload": {"action": "wire $5000 to external account"},
        "config": "policy",
        "why": "denylist is the bluntest deny path; a refactor must not drop it",
    },
    {
        "probe": "argument-denylist",
        "tool": "Bash",
        "kind": "shell",
        "payload": {"command": "rm -rf /"},
        "config": "policy",
        "why": "argument-level policy on the command payload",
    },
    {
        "probe": "composition-forbidden-sequence",
        "tool": "HTTPSend",
        "kind": "network",
        "payload": {"action": "POST /upload"},
        "config": "composition",
        "setup": (("Read", "read", {}),),
        "why": "read_sensitive -> external_send is the canonical exfil shape",
    },
    {
        "probe": "ceiling-fail-closed",
        "tool": "BankTransfer",
        "kind": "mutating",
        "payload": {},
        "config": "ceiling",
        "why": "ceiling ascent with no host callback must fail closed",
    },
    {
        "probe": "mutating-no-callback",
        "tool": "DeleteVolume",
        "kind": "mutating",
        "payload": {"action": "delete production volume"},
        "config": "plain",
        "why": "default-mode fail closed for mutating calls with no approver",
    },
)


def _build_engine(config_name: str):  # -> PermissionEngine
    """Build a fresh engine for one canary evaluation.

    Fresh per probe: engines carry call history (composition) and scope
    state (ceiling), so sharing one engine across canaries would let one
    probe's setup contaminate another's verdict.
    """
    from permissions import (
        ArgumentPolicy,
        CompositionRule,
        PermissionConfig,
        PermissionEngine,
        ScopeManager,
    )

    if config_name == "policy":
        return PermissionEngine(
            PermissionConfig(
                mode="default",
                can_use_tool=lambda n, p, c: True,
                disallowed_tools=("BankTransfer", "SendEmail"),
                argument_policies=(
                    ArgumentPolicy(
                        tool="Bash", argument="command", denylist=("rm -rf /",)
                    ),
                ),
            ),
            tool_kinds={
                "BankTransfer": "mutating",
                "SendEmail": "network",
                "Bash": "shell",
            },
        )
    if config_name == "composition":
        return PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            composition_rules=(
                CompositionRule(
                    sequence=("read_sensitive", "external_send"),
                    description="read then exfiltrate",
                ),
            ),
            tool_categories={"Read": "read_sensitive", "HTTPSend": "external_send"},
            tool_kinds={"Read": "read", "HTTPSend": "network"},
        )
    if config_name == "ceiling":
        mgr = ScopeManager()
        mgr.open_scope("canary-scope", "deny canary", capabilities=("Read", "Write"))
        return PermissionEngine(
            PermissionConfig(mode="default"),
            tool_kinds={"BankTransfer": "mutating"},
            scope_manager=mgr,
        )
    if config_name == "plain":
        return PermissionEngine(
            PermissionConfig(mode="default"),
            tool_kinds={"DeleteVolume": "mutating"},
        )
    raise ValueError(f"unknown deny-canary config: {config_name!r}")


def build_gate_fn() -> Callable[[dict[str, Any]], Any]:
    """Return ``gate_fn(probe) -> PermissionDecision`` for the canary corpus."""

    def gate_fn(probe: dict[str, Any]) -> Any:
        from permissions import PermissionRequestContext

        engine = _build_engine(probe["config"])
        for tool, kind, payload in probe.get("setup", ()):
            engine.evaluate(tool, kind=kind, payload=dict(payload))
        context = None
        if probe["config"] == "ceiling":
            context = PermissionRequestContext(scope_id="canary-scope")
        return engine.evaluate(
            probe["tool"],
            kind=probe["kind"],
            payload=dict(probe["payload"]),
            context=context,
        )

    return gate_fn


def compute_deny_set(
    corpus: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    gate_fn: Callable[[dict[str, Any]], Any],
) -> set[tuple[str, str]]:
    """Run the corpus through ``gate_fn``; return denied ``(probe, deny_code)`` pairs.

    Allowed probes contribute nothing: the deny set only tracks what the
    gate *refuses*. Deny codes come from the decision's machine-readable
    ``deny_code`` field (never parsed from free text).
    """
    denied: set[tuple[str, str]] = set()
    for probe in corpus:
        decision = gate_fn(probe)
        if not decision.allowed:
            code = decision.deny_code or "denial.unspecified"
            denied.add((str(probe["probe"]), str(code)))
    return denied


def check_monotonicity(
    old_deny_set: set[tuple[str, str]],
    new_deny_set: set[tuple[str, str]],
) -> tuple[bool, list[tuple[str, str]]]:
    """True iff ``new`` keeps every denial in ``old``.

    Returns ``(is_monotonic, loosened)`` where ``loosened`` is the sorted
    list of ``(probe, deny_code)`` pairs present in the baseline but
    absent now -- each one a denial the gate silently dropped.
    """
    old = set(old_deny_set)
    new = set(new_deny_set)
    loosened = sorted(old - new)
    return (not loosened, loosened)


def baseline_path() -> Path:
    """Filesystem path of the pinned baseline JSON (next to this module)."""
    return Path(__file__).with_name(BASELINE_FILENAME)


def save_baseline(
    deny_set: set[tuple[str, str]], path: str | Path | None = None
) -> Path:
    """Write the deny set as the pinned baseline. Deliberate, reviewed act."""
    target = Path(path) if path is not None else baseline_path()
    payload = {
        "version": DENY_MONOTONICITY_VERSION,
        "deny_set": sorted([list(pair) for pair in deny_set]),
    }
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return target


def load_baseline(path: str | Path | None = None) -> set[tuple[str, str]]:
    """Load the pinned baseline. Raises FileNotFoundError when absent.

    Fail-closed by design: without a pinned baseline there is nothing to
    be monotone against, so the bench must not silently pass.
    """
    target = Path(path) if path is not None else baseline_path()
    raw = json.loads(target.read_text())
    return {(str(p), str(c)) for p, c in raw["deny_set"]}


def regenerate_baseline(
    corpus: tuple[dict[str, Any], ...] | None = None,
    path: str | Path | None = None,
) -> Path:
    """Recompute the deny set against the *current* gate and pin it.

    Call this only after reviewing *why* the deny set changed: every
    added or removed pair is a gate-behavior change that deserves a human
    look before it becomes the new floor.
    """
    deny_set = compute_deny_set(corpus or DENY_CORPUS, build_gate_fn())
    return save_baseline(deny_set, path)


def deny_monotonicity_check(
    gate_fn: Callable[[dict[str, Any]], Any] | None = None,
    corpus: tuple[dict[str, Any], ...] | None = None,
    baseline: str | Path | None = None,
) -> tuple[bool, str]:
    """Bench-ready check: ``(ok, message)`` for the deny-monotonicity case.

    Compares the current gate's deny set against the pinned baseline.
    ``ok`` is False when any baseline denial is gone (or when the
    baseline itself is missing -- fail closed). Wire this as a bench
    ``post_check``.
    """
    entries = corpus or DENY_CORPUS
    try:
        pinned = load_baseline(baseline)
    except FileNotFoundError:
        return (
            False,
            "deny-monotonicity baseline missing: regenerate with "
            "deny_monotonicity.regenerate_baseline() after review",
        )
    current = compute_deny_set(entries, gate_fn or build_gate_fn())
    ok, loosened = check_monotonicity(pinned, current)
    added = sorted(current - pinned)
    if not ok:
        detail = "; ".join(f"{p} [{c}]" for p, c in loosened)
        return (
            False,
            f"deny-monotonicity violated: {len(loosened)} baseline denial(s) "
            f"lost: {detail}",
        )
    return (
        True,
        f"deny-monotonicity holds: {len(current)} denials, "
        f"{len(added)} added since baseline, 0 lost",
    )
