"""Isolated Git workspaces and evidence artifacts for ``northstar code``.

The model never works in the caller's checkout.  A detached worktree is created from
the exact starting commit, and the final patch is captured before the disposable tree
is removed.  Failed runs keep their tree so a human can reconcile uncertain state.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_FILES = 8_000
MAX_DELIVERY_PATCH_BYTES = 8 * 1024 * 1024
MAX_DELIVERY_FILE_BYTES = 1024 * 1024
MAX_DELIVERY_FILES = 200

_GENERATED_PARTS = frozenset({"build", "dist", "node_modules", "__pycache__"})
_GENERATED_SUFFIXES = frozenset(
    {".class", ".dll", ".dylib", ".exe", ".o", ".obj", ".pyc", ".so", ".whl", ".zip"}
)
_SECRET_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b")),
)


def append_code_protocol(
    system_prompt: str,
    *,
    checks: Sequence[str] = (),
    plan_only: bool = False,
) -> str:
    """Append the host-owned programming workflow to an existing system prompt."""
    check_lines = (
        "\n".join(f"  {index}: {command}" for index, command in enumerate(checks))
        if checks
        else "  (none declared; the final outcome will be marked success_unverified)"
    )
    execution = (
        "This is a plan-only run. Inspect the repository and return a concrete plan; do not edit files or execute commands."
        if plan_only
        else (
            "Make the smallest coherent change that completes the task. Prefer ApplyPatch for multi-line edits, "
            "and inspect the final patch with GitInspect. Do not commit, push, or modify Git metadata."
        )
    )
    return (
        system_prompt.rstrip()
        + "\n\n== Northstar code task protocol (host-authored) ==\n"
        + "Work in four explicit phases: Understand, Plan, Execute, Verify. Read repository instructions and map the relevant code before editing.\n"
        + "After understanding the relevant code, you MUST call SubmitPlan exactly once with the files, ordered steps, risks, and declared check indices. "
        + "Effectful tools are host-gated until that structured plan is accepted. Do not finish before SubmitPlan succeeds.\n"
        + execution
        + "\nRunCheck accepts only these host-declared checks by zero-based index:\n"
        + check_lines
        + "\nA check you run during development does not replace the independent completion check. "
        + "When you finish, report files changed, behavior delivered, checks run, and any remaining uncertainty.\n"
        + "== End Northstar code task protocol =="
    )


class CodeTaskError(ValueError):
    """The requested code workspace cannot be prepared or evidenced safely."""


CODE_PHASE_TERMINALS = frozenset(
    {
        "success",
        "success_unverified",
        "error_max_turns",
        "error_max_tool_calls",
        "error_max_budget_usd",
        "error_during_execution",
        "error_permission_denied",
        "error_postconditions_failed",
        "error_session_busy",
    }
)


class CodePhaseMachine:
    """Host-owned phase gate with a durable, atomic transition journal.

    The model advances ``understanding -> planned`` only through SubmitPlan.
    The runtime advances the remaining phases immediately before an approved
    effect and before independent verification. Terminal outcomes may close any
    active phase so provider, budget, and permission failures are still recorded.
    """

    _FORWARD = {
        "created": frozenset({"understanding"}),
        "understanding": frozenset({"planned"}),
        "planned": frozenset({"executing", "verifying"}),
        "executing": frozenset({"verifying"}),
        "verifying": frozenset(),
    }

    def __init__(
        self,
        *,
        run_id: str,
        evidence_dir: str | Path,
        plan_only: bool = False,
        worktree: str | Path | None = None,
        start_commit: str = "",
    ) -> None:
        if not isinstance(run_id, str) or not run_id.strip():
            raise CodeTaskError("code phase machine needs a run id")
        self.run_id = run_id
        self.plan_only = bool(plan_only)
        self.path = Path(evidence_dir) / "phases.json"
        self.worktree = Path(worktree).resolve() if worktree is not None else None
        self.start_commit = start_commit
        self._state = "created"
        self._outcome: str | None = None
        self._transitions: list[dict[str, Any]] = []
        self._plan: dict[str, Any] | None = None
        self._effects: list[dict[str, Any]] = []
        self._verification_patch_sha256: str | None = None
        self._delivery_sealed = False
        self._lock = threading.RLock()
        self._persist()

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def outcome(self) -> str | None:
        with self._lock:
            return self._outcome

    @property
    def plan_submitted(self) -> bool:
        with self._lock:
            return self._plan is not None

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": "northstar.code-phases.v1",
            "run_id": self.run_id,
            "state": self._state,
            "outcome": self._outcome,
            "plan_only": self.plan_only,
            "plan": self._plan,
            "transitions": list(self._transitions),
            "effect_journal_version": 1,
            "effects": [dict(effect) for effect in self._effects],
        }

    def _persist(self) -> None:
        raw = (
            json.dumps(self._payload(), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        _atomic_write(self.path, raw)

    def _transition(self, target: str, *, reason: str, data: dict[str, Any] | None = None) -> None:
        if self._outcome is not None:
            raise CodeTaskError(f"code phase is already terminal: {self._outcome}")
        allowed = self._FORWARD.get(self._state, frozenset())
        if target not in allowed:
            raise CodeTaskError(f"invalid code phase transition: {self._state} -> {target}")
        previous = self._state
        self._state = target
        self._transitions.append(
            {
                "sequence": len(self._transitions) + 1,
                "from": previous,
                "to": target,
                "reason": reason,
                "data": dict(data or {}),
                "timestamp_unix_ms": int(time.time() * 1000),
            }
        )
        self._persist()

    def start(self) -> None:
        with self._lock:
            if self._state == "created":
                self._transition("understanding", reason="repository snapshot recorded")

    def submit_plan(self, plan: dict[str, Any]) -> None:
        with self._lock:
            if self._state != "understanding":
                raise CodeTaskError(f"SubmitPlan is only valid during understanding, not {self._state}")
            if self._plan is not None:
                raise CodeTaskError("a code task accepts exactly one submitted plan")
            self._plan = dict(plan)
            self._transition(
                "planned",
                reason="model submitted a structured plan",
                data={
                    "files": len(plan.get("files", ())),
                    "steps": len(plan.get("steps", ())),
                    "risks": len(plan.get("risks", ())),
                    "checks": len(plan.get("check_indices", ())),
                },
            )

    def begin_execution(self, *, tool: str, call_id: str = "") -> str:
        """Durably record an approved effect immediately before its handler runs."""
        with self._lock:
            if self.plan_only:
                raise CodeTaskError("plan-only code tasks cannot enter execution")
            if self._state == "planned":
                self._transition(
                    "executing",
                    reason="approved effect is about to execute",
                    data={"tool": tool, "call_id": call_id},
                )
            elif self._state != "executing":
                raise CodeTaskError(
                    f"{tool} requires a submitted plan before execution; current phase is {self._state}"
                )
            return self._start_effect(tool=tool, call_id=call_id)

    def _start_effect(self, *, tool: str, call_id: str) -> str:
        effect_id = f"effect-{len(self._effects) + 1}"
        self._effects.append(
            {
                "effect_id": effect_id,
                "sequence": len(self._effects) + 1,
                "tool": str(tool),
                "call_id": str(call_id),
                "phase": self._state,
                "status": "in_flight",
                "started_unix_ms": int(time.time() * 1000),
                "finished_unix_ms": None,
                "error_class": "",
            }
        )
        self._persist()
        return effect_id

    def begin_check(self, *, index: int) -> str:
        """Record a host verification command before entering the sandbox."""
        with self._lock:
            if self._state != "verifying" or self._outcome is not None:
                raise CodeTaskError("host checks require the verifying phase")
            return self._start_effect(tool="HostCheck", call_id=f"verification-{index}")

    def complete_execution(
        self,
        effect_id: str,
        *,
        status: str,
        error_class: str = "",
    ) -> None:
        """Close one effect receipt; a crash before this call leaves it unknown."""
        if status not in {"completed", "failed", "unknown"}:
            raise CodeTaskError(f"invalid effect completion status: {status}")
        with self._lock:
            effect = next(
                (item for item in self._effects if item["effect_id"] == effect_id),
                None,
            )
            if effect is None:
                raise CodeTaskError(f"unknown code effect: {effect_id}")
            if effect["status"] != "in_flight":
                raise CodeTaskError(
                    f"code effect {effect_id} is already {effect['status']}"
                )
            previous = dict(effect)
            effect["status"] = status
            effect["finished_unix_ms"] = int(time.time() * 1000)
            effect["error_class"] = str(error_class)[:200]
            try:
                self._persist()
            except BaseException:
                effect.clear()
                effect.update(previous)
                raise

    def begin_verification(self) -> None:
        with self._lock:
            in_flight = [
                effect["effect_id"]
                for effect in self._effects
                if effect["status"] in {"in_flight", "unknown"}
            ]
            if in_flight:
                raise CodeTaskError(
                    "verification cannot begin with effects lacking completion receipts: "
                    + ", ".join(in_flight)
                )
            if self.plan_only:
                if self._state != "planned":
                    raise CodeTaskError("plan-only task ended before SubmitPlan")
                return
            if self._state in {"planned", "executing"}:
                self._transition("verifying", reason="model stopped; host verification begins")
            elif self._state != "verifying":
                raise CodeTaskError(
                    "verification requires a successful SubmitPlan call; "
                    f"current phase is {self._state}"
                )
            if self.worktree is not None:
                receipt = validate_patch_replay(
                    self.worktree,
                    start_commit=self.start_commit,
                    evidence_dir=self.path.parent,
                )
                self._verification_patch_sha256 = receipt["patch_sha256"]
                if not receipt["ok"]:
                    raise CodeTaskError(
                        "final patch cannot be replayed from the starting commit: "
                        + str(receipt.get("diagnostic") or "git apply check failed")
                    )
                audit = audit_delivery_patch(
                    self.worktree,
                    evidence_dir=self.path.parent,
                )
                if not audit["ok"]:
                    codes = ", ".join(
                        sorted({str(item.get("code", "unknown")) for item in audit["findings"]})
                    )
                    raise CodeTaskError(f"final patch failed delivery audit: {codes}")

    def seal_verification(self) -> None:
        """Prove host checks did not change the audited delivery patch."""
        with self._lock:
            if self.plan_only or self.worktree is None:
                return
            if self._state != "verifying" or self._verification_patch_sha256 is None:
                raise CodeTaskError("delivery sealing requires completed patch prechecks")
            audit = audit_delivery_patch(self.worktree, evidence_dir=self.path.parent)
            unchanged = audit["patch_sha256"] == self._verification_patch_sha256
            receipt = {
                "schema": "northstar.delivery-seal.v1",
                "start_commit": self.start_commit,
                "precheck_patch_sha256": self._verification_patch_sha256,
                "patch_sha256": audit["patch_sha256"],
                "unchanged_during_verification": unchanged,
                "patch_audit_ok": bool(audit["ok"]),
                "ok": unchanged and bool(audit["ok"]),
            }
            _atomic_write(
                self.path.parent / "delivery-seal.json",
                (json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
            )
            self._delivery_sealed = bool(receipt["ok"])
            if not unchanged:
                raise CodeTaskError("host verification modified the audited delivery patch")
            if not audit["ok"]:
                raise CodeTaskError("delivery audit failed after host verification")

    def finish(self, outcome: str, *, reason: str = "runtime terminal result") -> None:
        with self._lock:
            if outcome not in CODE_PHASE_TERMINALS:
                raise CodeTaskError(f"unknown code task terminal outcome: {outcome}")
            if self._outcome is not None:
                if self._outcome != outcome:
                    raise CodeTaskError(
                        f"code task already ended as {self._outcome}, cannot replace it with {outcome}"
                    )
                return
            if outcome in {"success", "success_unverified"} and any(
                effect["status"] in {"in_flight", "unknown"} for effect in self._effects
            ):
                raise CodeTaskError("a successful code run cannot contain an in-flight effect")
            if outcome in {"success", "success_unverified"} and self._state != (
                "planned" if self.plan_only else "verifying"
            ):
                raise CodeTaskError("a successful code run must complete its phase protocol")
            if outcome in {"success", "success_unverified"} and self.worktree is not None and not self.plan_only and not self._delivery_sealed:
                raise CodeTaskError("a successful code run must seal its delivery after host verification")
            previous = self._state
            self._outcome = outcome
            self._state = outcome
            self._transitions.append(
                {
                    "sequence": len(self._transitions) + 1,
                    "from": previous,
                    "to": outcome,
                    "reason": reason,
                    "data": {},
                    "timestamp_unix_ms": int(time.time() * 1000),
                }
            )
            self._persist()

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            return self._payload()


def _run_git(
    root: Path,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.run(
        ["git", "-C", str(root), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if len(process.stdout) > MAX_GIT_OUTPUT_BYTES or len(process.stderr) > MAX_GIT_OUTPUT_BYTES:
        raise CodeTaskError("git output exceeded the 64 MiB evidence limit")
    if check and process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise CodeTaskError(f"git {' '.join(arguments)} failed: {detail or process.returncode}")
    return process


def _current_patch(worktree: Path) -> bytes:
    """Return one binary-capable patch containing tracked and untracked changes."""
    _run_git(worktree, "add", "--intent-to-add", "--all")
    return _run_git(
        worktree,
        "diff",
        "--binary",
        "--no-ext-diff",
        "--full-index",
        "HEAD",
        "--",
    ).stdout


def validate_patch_replay(
    worktree: str | Path,
    *,
    start_commit: str,
    evidence_dir: str | Path,
) -> dict[str, Any]:
    """Check the final patch against a temporary index seeded from start_commit."""
    root = Path(worktree).resolve()
    destination = Path(evidence_dir).resolve() / "patch-replay.json"
    patch = _current_patch(root)
    read_tree_exit = 0
    apply_exit = 0
    diagnostic = ""
    if patch:
        handle, raw_index = tempfile.mkstemp(prefix=".patch-replay-index.", dir=destination.parent)
        os.close(handle)
        index = Path(raw_index)
        index.unlink()
        environment = dict(os.environ)
        environment.update(
            {
                "GIT_INDEX_FILE": str(index),
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C.UTF-8",
            }
        )
        try:
            seeded = subprocess.run(
                ["git", "-C", str(root), "read-tree", start_commit],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                check=False,
            )
            read_tree_exit = seeded.returncode
            if seeded.returncode == 0:
                checked = subprocess.run(
                    ["git", "-C", str(root), "apply", "--check", "--cached", "--binary", "-"],
                    input=patch,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=environment,
                    check=False,
                )
                apply_exit = checked.returncode
                diagnostic = (checked.stderr or checked.stdout).decode(
                    "utf-8", errors="replace"
                ).strip()[:4_000]
            else:
                apply_exit = -1
                diagnostic = (seeded.stderr or seeded.stdout).decode(
                    "utf-8", errors="replace"
                ).strip()[:4_000]
        finally:
            try:
                index.unlink()
            except FileNotFoundError:
                pass
    receipt = {
        "schema": "northstar.patch-replay.v1",
        "start_commit": start_commit,
        "patch_bytes": len(patch),
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
        "empty": not bool(patch),
        "read_tree_exit_code": read_tree_exit,
        "apply_exit_code": apply_exit,
        "ok": read_tree_exit == 0 and apply_exit == 0,
        "diagnostic": diagnostic,
    }
    _atomic_write(
        destination,
        (json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    )
    return receipt


def audit_delivery_patch(
    worktree: str | Path,
    *,
    evidence_dir: str | Path,
) -> dict[str, Any]:
    """Reject high-confidence delivery hazards after every model tool has stopped."""
    root = Path(worktree).resolve()
    destination = Path(evidence_dir).resolve() / "patch-audit.json"
    patch = _current_patch(root)
    names_process = _run_git(root, "diff", "--name-only", "-z", "HEAD", "--")
    paths = tuple(
        item for item in names_process.stdout.decode("utf-8", errors="replace").split("\0") if item
    )
    findings: list[dict[str, str]] = []

    def finding(code: str, path: str, detail: str) -> None:
        findings.append({"code": code, "path": path, "detail": detail})

    if len(patch) > MAX_DELIVERY_PATCH_BYTES:
        finding(
            "patch_too_large",
            "(patch)",
            f"delivery patch is {len(patch)} bytes; cap is {MAX_DELIVERY_PATCH_BYTES}",
        )
    if len(paths) > MAX_DELIVERY_FILES:
        finding(
            "too_many_files",
            "(patch)",
            f"delivery changes {len(paths)} files; cap is {MAX_DELIVERY_FILES}",
        )

    for raw_path in paths[: MAX_DELIVERY_FILES + 1]:
        path = Path(raw_path)
        parts = set(path.parts)
        if path.parts and path.parts[0] in {".git", ".northstar"}:
            finding(
                "governance_path_changed",
                raw_path,
                "delivery may not modify repository metadata or Northstar governance",
            )
        if parts & _GENERATED_PARTS or path.suffix.lower() in _GENERATED_SUFFIXES:
            finding(
                "generated_artifact",
                raw_path,
                "generated or dependency artifacts are excluded from code-task delivery",
            )
        target = (root / path).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            finding("path_escape", raw_path, "changed path resolves outside the task worktree")
            continue
        if target.exists() and target.is_file():
            try:
                size = target.stat().st_size
            except OSError:
                size = MAX_DELIVERY_FILE_BYTES + 1
            if size > MAX_DELIVERY_FILE_BYTES:
                finding(
                    "large_file",
                    raw_path,
                    f"changed file is {size} bytes; cap is {MAX_DELIVERY_FILE_BYTES}",
                )

    patch_text = patch.decode("utf-8", errors="replace")
    if any(marker in patch_text for marker in ("new file mode 120000", "new file mode 160000")):
        finding("special_file", "(patch)", "symlinks and submodules are excluded from delivery")
    added_text = "\n".join(
        line[1:]
        for line in patch_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    for code, pattern in _SECRET_PATTERNS:
        if pattern.search(added_text):
            finding(code, "(patch)", "new content matches a high-confidence credential pattern")

    receipt = {
        "schema": "northstar.patch-audit.v1",
        "ok": not findings,
        "changed_files": len(paths),
        "patch_bytes": len(patch),
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
        "findings": findings,
    }
    _atomic_write(
        destination,
        (json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    )
    return receipt


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, raw_temp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(raw_temp)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read_evidence_json(evidence_dir: Path, name: str) -> tuple[dict[str, Any], bytes]:
    path = evidence_dir / name
    if path.is_symlink() or not path.is_file():
        raise CodeTaskError(f"code evidence is missing a regular {name}")
    try:
        if path.stat().st_size > 4 * 1024 * 1024:
            raise CodeTaskError(f"code evidence {name} exceeds 4 MiB")
        raw = path.read_bytes()
        payload = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise CodeTaskError(f"cannot read code evidence {name}: {error}") from error
    if not isinstance(payload, dict):
        raise CodeTaskError(f"code evidence {name} must contain a JSON object")
    return payload, raw


def reconcile_code_evidence(evidence_dir: str | Path) -> dict[str, Any]:
    """Classify an interrupted code run without replaying any tool effect.

    An effect with no completion record or an uncertain handler exception is
    reported for manual review. This function never re-runs a tool, removes a
    worktree, or changes the original manifest/phase journal.
    """
    root = Path(evidence_dir).expanduser().resolve()
    if not root.is_dir():
        raise CodeTaskError(f"code evidence directory does not exist: {root}")
    manifest, _ = _read_evidence_json(root, "manifest.json")
    phases, phase_raw = _read_evidence_json(root, "phases.json")
    integrity_errors: list[str] = []
    if manifest.get("schema") != "northstar.code-evidence.v1":
        integrity_errors.append("unsupported manifest schema")
    if phases.get("schema") != "northstar.code-phases.v1":
        integrity_errors.append("unsupported phase schema")
    run_id = str(phases.get("run_id") or "")
    if not run_id or run_id != str(manifest.get("run_id") or ""):
        integrity_errors.append("manifest and phase run ids do not match")
    sealed_digest = manifest.get("phases_sha256")
    actual_digest = hashlib.sha256(phase_raw).hexdigest()
    phase_seal = "absent"
    if sealed_digest is not None:
        phase_seal = "valid" if sealed_digest == actual_digest else "invalid"
        if phase_seal == "invalid":
            integrity_errors.append("phase journal digest does not match the manifest")

    # A phase seal alone cannot cover a changed task, snapshot, patch or receipt.
    for digest_key, expected in manifest.items():
        if not digest_key.endswith("_sha256") or digest_key == "phases_sha256":
            continue
        artifact_key = digest_key.removesuffix("_sha256")
        artifact = manifest.get(artifact_key)
        if not isinstance(artifact, str) or Path(artifact).name != artifact or artifact in {".", ".."}:
            integrity_errors.append(f"{artifact_key} artifact path is invalid")
            continue
        path = root / artifact
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_GIT_OUTPUT_BYTES:
                raise CodeTaskError("artifact is missing, special, or oversized")
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                integrity_errors.append(f"{artifact_key} digest does not match the manifest")
        except (OSError, CodeTaskError) as error:
            integrity_errors.append(f"{artifact_key}: {error}")

    active_states = set(CodePhaseMachine._FORWARD)
    state = str(phases.get("state") or "")
    outcome = phases.get("outcome")
    if state not in active_states and state not in CODE_PHASE_TERMINALS:
        integrity_errors.append(f"unknown phase state: {state or '(empty)'}")
    if outcome is not None and (
        not isinstance(outcome, str) or outcome not in CODE_PHASE_TERMINALS or state != outcome
    ):
        integrity_errors.append("terminal outcome and phase state are inconsistent")
    if state in CODE_PHASE_TERMINALS and outcome != state:
        integrity_errors.append("terminal phase is missing its matching outcome")

    transitions = phases.get("transitions")
    previous_state = "created"
    if not isinstance(transitions, list):
        integrity_errors.append("phase transitions must be an array")
        transitions = []
    for index, transition in enumerate(transitions):
        if not isinstance(transition, dict):
            integrity_errors.append(f"transition {index + 1} is not an object")
            continue
        target = transition.get("to")
        if transition.get("sequence") != index + 1 or transition.get("from") != previous_state:
            integrity_errors.append(f"transition {index + 1} breaks the phase chain")
        if not isinstance(target, str) or (
            target not in CodePhaseMachine._FORWARD.get(previous_state, ())
            and not (previous_state in active_states and target in CODE_PHASE_TERMINALS)
        ):
            integrity_errors.append(f"transition {index + 1} is not allowed")
        previous_state = target if isinstance(target, str) else ""
    if previous_state != state:
        integrity_errors.append("phase state does not match the transition chain")

    raw_effects = phases.get("effects", [])
    if not isinstance(raw_effects, list):
        integrity_errors.append("phase effects must be an array")
        raw_effects = []
    effects: list[dict[str, Any]] = []
    seen_effect_ids: set[str] = set()
    for index, raw_effect in enumerate(raw_effects):
        if not isinstance(raw_effect, dict):
            integrity_errors.append(f"effect {index + 1} is not an object")
            continue
        effect_id = str(raw_effect.get("effect_id") or "")
        status = str(raw_effect.get("status") or "")
        if not effect_id or effect_id in seen_effect_ids:
            integrity_errors.append(f"effect {index + 1} has a missing or duplicate id")
        seen_effect_ids.add(effect_id)
        if status not in {"in_flight", "completed", "failed", "unknown"}:
            integrity_errors.append(f"effect {effect_id or index + 1} has an invalid status")
        if raw_effect.get("sequence") != index + 1:
            integrity_errors.append(f"effect {effect_id or index + 1} has an invalid sequence")
        started = raw_effect.get("started_unix_ms")
        finished = raw_effect.get("finished_unix_ms")
        if type(started) is not int or started < 0:
            integrity_errors.append(f"effect {effect_id or index + 1} is missing its start timestamp")
        elif status == "in_flight" and finished is not None:
            integrity_errors.append(f"effect {effect_id or index + 1} has inconsistent completion fields")
        elif status != "in_flight" and (type(finished) is not int or finished < started):
            integrity_errors.append(f"effect {effect_id or index + 1} is missing its completion timestamp")
        effects.append(
            {
                "effect_id": effect_id,
                "sequence": raw_effect.get("sequence"),
                "tool": str(raw_effect.get("tool") or ""),
                "call_id": str(raw_effect.get("call_id") or ""),
                "phase": str(raw_effect.get("phase") or ""),
                "status": status,
                "started_unix_ms": raw_effect.get("started_unix_ms"),
                "finished_unix_ms": raw_effect.get("finished_unix_ms"),
                "error_class": str(raw_effect.get("error_class") or "")[:200],
            }
        )
    unknown = [effect for effect in effects if effect["status"] in {"in_flight", "unknown", "failed"}]
    effect_journal_complete = phases.get("effect_journal_version") == 1
    worktree_value = manifest.get("worktree")
    worktree_exists = bool(
        isinstance(worktree_value, str)
        and worktree_value
        and Path(worktree_value).expanduser().is_dir()
    )

    if integrity_errors:
        classification = "invalid_evidence"
        next_action = "repair or independently inspect the evidence before any restart"
    elif unknown:
        classification = "manual_review_required"
        next_action = "inspect the retained worktree and external systems; never replay the listed effects automatically"
    elif isinstance(outcome, str) and outcome in CODE_PHASE_TERMINALS and (
        phase_seal != "valid" or manifest.get("status") != outcome
    ):
        classification = "incomplete_terminal_evidence"
        next_action = "inspect the retained state; the phase outcome was not fully sealed and captured"
    elif not effect_journal_complete:
        classification = "insufficient_effect_evidence"
        next_action = "inspect legacy evidence manually; the effect journal cannot establish whether tools executed"
    elif isinstance(outcome, str) and outcome in CODE_PHASE_TERMINALS:
        classification = "terminal"
        next_action = "use the sealed terminal evidence; no recovery action is required"
    elif not effects:
        classification = "interrupted_before_effects"
        next_action = "start a new run from the recorded commit; phase resume is not implemented"
    else:
        classification = "interrupted_after_receipted_effects"
        next_action = "inspect the retained worktree, then start a new run or wait for phase-resume support"

    receipt = {
        "schema": "northstar.code-reconcile.v1",
        "run_id": run_id,
        "classification": classification,
        "state": state,
        "outcome": outcome,
        "phase_seal": phase_seal,
        "effect_journal_complete": effect_journal_complete,
        "phase_sha256": actual_digest,
        "integrity_errors": integrity_errors,
        "effect_counts": dict(Counter(effect["status"] for effect in effects)),
        "unknown_side_effects": unknown,
        "worktree": worktree_value,
        "worktree_exists": worktree_exists,
        "automatic_tool_replay": False,
        "phase_resume_supported": False,
        "safe_restart_from_start_commit": (
            not integrity_errors
            and effect_journal_complete
            and not effects
            and state in {"created", "understanding", "planned"}
        ),
        "next_action": next_action,
    }
    _atomic_write(
        root / "reconcile.json",
        (json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    )
    return receipt


def default_state_root() -> Path:
    """Host state directory used when the caller did not choose an evidence path."""
    configured = os.environ.get("XDG_STATE_HOME", "").strip()
    base = Path(configured).expanduser() if configured else Path.home() / ".local" / "state"
    return (base / "northstar" / "code-runs").resolve()


@dataclass(frozen=True)
class CodeTask:
    """The host-owned task contract for one programming run."""

    goal: str
    workspace: str = "."
    checks: tuple[str, ...] = ()
    plan_only: bool = False
    network_targets: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.goal, str) or not self.goal.strip():
            raise CodeTaskError("a code task needs a non-empty goal")
        if self.goal != self.goal.strip():
            raise CodeTaskError("the code task goal must not have leading or trailing whitespace")
        if not isinstance(self.checks, tuple) or any(
            not isinstance(command, str) or not command.strip() for command in self.checks
        ):
            raise CodeTaskError("checks must be a tuple of non-empty command strings")

    def as_dict(self) -> dict[str, Any]:
        return {
            "goal": self.goal,
            "checks": list(self.checks),
            "plan_only": self.plan_only,
            "network_targets": list(self.network_targets),
        }


@dataclass
class IsolatedCodeWorkspace:
    """Lifecycle of a detached task worktree and its durable evidence directory."""

    source: str | Path
    evidence_root: str | Path | None = None
    run_id: str = field(default_factory=lambda: f"code-{int(time.time())}-{uuid.uuid4().hex[:10]}")
    repository: Path | None = None
    start_commit: str = ""
    source_branch: str = ""
    source_relative: str = "."
    source_status: tuple[str, ...] = ()
    worktree: Path | None = None
    evidence_dir: Path | None = None
    _temporary_parent: Path | None = None

    def prepare(self) -> "IsolatedCodeWorkspace":
        source = Path(self.source).expanduser().resolve()
        if not source.is_dir():
            raise CodeTaskError(f"code workspace is not a directory: {source}")
        top = _run_git(source, "rev-parse", "--show-toplevel").stdout.decode().strip()
        repository = Path(top).resolve()
        try:
            source_relative = source.relative_to(repository)
        except ValueError as error:
            raise CodeTaskError(f"workspace {source} is outside Git repository {repository}") from error
        start_commit = _run_git(repository, "rev-parse", "HEAD").stdout.decode().strip()
        if len(start_commit) != 40:
            raise CodeTaskError("Git HEAD did not resolve to a full commit id")

        source_status = tuple(
            _run_git(repository, "status", "--short", "--untracked-files=all")
            .stdout.decode("utf-8", errors="replace")
            .splitlines()
        )
        source_branch_process = _run_git(
            repository, "symbolic-ref", "--short", "-q", "HEAD", check=False
        )
        source_branch = source_branch_process.stdout.decode("utf-8", errors="replace").strip()
        parent = Path(tempfile.mkdtemp(prefix="northstar-code-"))
        worktree = parent / "worktree"
        try:
            _run_git(repository, "worktree", "add", "--detach", str(worktree), start_commit)
        except Exception:
            try:
                parent.rmdir()
            except OSError:
                pass
            raise

        try:
            evidence_base = (
                Path(self.evidence_root).expanduser().resolve()
                if self.evidence_root is not None
                else default_state_root()
            )
            evidence_dir = evidence_base / self.run_id
            evidence_dir.mkdir(parents=True, exist_ok=False)

            self.repository = repository
            self.start_commit = start_commit
            self.source_branch = source_branch
            self.source_relative = source_relative.as_posix() or "."
            self.source_status = source_status
            self.worktree = worktree
            self.evidence_dir = evidence_dir
            self._temporary_parent = parent
            self._write_manifest({"status": "prepared"})
            self.record_repository_snapshot()
        except Exception:
            # Preparing evidence is part of preparing the run. Do not leak a
            # registered worktree when that second half cannot complete.
            _run_git(repository, "worktree", "remove", "--force", str(worktree), check=False)
            _run_git(repository, "worktree", "prune", check=False)
            try:
                parent.rmdir()
            except OSError:
                pass
            raise
        return self

    @property
    def execution_root(self) -> Path:
        """Workspace equivalent to the caller's path inside the detached tree."""
        if self.worktree is None:
            raise CodeTaskError("code workspace has not been prepared")
        target = (self.worktree / self.source_relative).resolve()
        if not target.is_dir():
            raise CodeTaskError(
                f"isolated workspace subdirectory is missing: {self.source_relative}"
            )
        return target

    @property
    def session_dir(self) -> Path:
        if self.evidence_dir is None:
            raise CodeTaskError("code workspace has not been prepared")
        return self.evidence_dir / "sessions"

    def _write_manifest(self, update: dict[str, Any]) -> None:
        if self.evidence_dir is None:
            return
        path = self.evidence_dir / "manifest.json"
        current: dict[str, Any] = {}
        if path.exists():
            try:
                current = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                current = {}
        current.update(
            {
                "schema": "northstar.code-evidence.v1",
                "run_id": self.run_id,
                "repository": str(self.repository) if self.repository else None,
                "start_commit": self.start_commit or None,
                "source_branch": self.source_branch or None,
                "source_relative": self.source_relative,
                "source_status": list(self.source_status),
                "worktree": str(self.worktree) if self.worktree else None,
                **update,
            }
        )
        _atomic_write(
            path,
            (json.dumps(current, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        )

    def record_repository_snapshot(self) -> Path:
        """Persist a bounded map of the exact clean tree handed to the agent."""
        if self.worktree is None or self.evidence_dir is None:
            raise CodeTaskError("code workspace has not been prepared")
        arguments = ["ls-files", "--cached", "-z"]
        prefix = "" if self.source_relative == "." else self.source_relative.rstrip("/") + "/"
        if prefix:
            arguments.extend(("--", self.source_relative))
        raw = _run_git(self.worktree, *arguments).stdout.decode("utf-8", errors="replace")
        repository_paths = sorted(item for item in raw.split("\0") if item)
        files = [
            path[len(prefix):] if prefix and path.startswith(prefix) else path
            for path in repository_paths
        ]
        selected = files[:MAX_SNAPSHOT_FILES]
        suffixes = Counter((Path(path).suffix.lower() or "[none]") for path in files)
        top_level = Counter(path.split("/", 1)[0] for path in files)
        landmark_names = {
            "agents.md", "cargo.toml", "go.mod", "makefile", "package.json",
            "pyproject.toml", "readme.md", "requirements.txt", "tox.ini",
        }
        landmarks = [path for path in files if Path(path).name.lower() in landmark_names][:64]
        payload = {
            "schema": "northstar.repository-snapshot.v1",
            "start_commit": self.start_commit,
            "source_branch": self.source_branch or None,
            "source_relative": self.source_relative,
            "source_dirty": bool(self.source_status),
            "source_status": list(self.source_status),
            "file_count": len(files),
            "files": selected,
            "files_truncated": len(files) > len(selected),
            "file_types": dict(suffixes.most_common(64)),
            "top_level": dict(top_level.most_common(128)),
            "landmarks": landmarks,
        }
        path = self.evidence_dir / "repository-snapshot.json"
        raw_payload = (
            json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        _atomic_write(path, raw_payload)
        self._write_manifest(
            {
                "repository_snapshot": path.name,
                "repository_snapshot_sha256": hashlib.sha256(raw_payload).hexdigest(),
            }
        )
        return path

    def record_task(self, task: CodeTask) -> Path:
        """Persist the immutable host task beside the run manifest."""
        if self.evidence_dir is None:
            raise CodeTaskError("code workspace has not been prepared")
        path = self.evidence_dir / "task.json"
        payload = task.as_dict()
        _atomic_write(
            path,
            (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        )
        self._write_manifest(
            {
                "task": path.name,
                "task_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
        return path

    def record_verification(self, summaries: Sequence[dict[str, Any]]) -> Path:
        """Persist independent completion receipts, including an explicit empty plan."""
        if self.evidence_dir is None:
            raise CodeTaskError("code workspace has not been prepared")
        path = self.evidence_dir / "verification.json"
        payload = {
            "schema": "northstar.code-verification.v1",
            "summaries": list(summaries),
        }
        raw = (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        _atomic_write(path, raw)
        all_ok = bool(summaries) and all(bool(summary.get("ok", False)) for summary in summaries)
        self._write_manifest(
            {
                "verification": path.name,
                "verification_sha256": hashlib.sha256(raw).hexdigest(),
                "verification_ok": all_ok,
            }
        )
        return path

    def record_phases(self, phases: CodePhaseMachine) -> Path:
        """Seal the latest phase journal into the top-level evidence manifest."""
        if self.evidence_dir is None:
            raise CodeTaskError("code workspace has not been prepared")
        path = phases.path
        try:
            if path.parent.resolve() != self.evidence_dir.resolve():
                raise CodeTaskError("phase evidence belongs to a different run directory")
            raw = path.read_bytes()
        except OSError as error:
            raise CodeTaskError(f"cannot read phase evidence: {error}") from error
        payload = phases.as_dict()
        update = {
            "phases": path.name,
            "phases_sha256": hashlib.sha256(raw).hexdigest(),
            "phase": payload["state"],
            "phase_outcome": payload["outcome"],
        }
        replay = self.evidence_dir / "patch-replay.json"
        if replay.is_file():
            replay_raw = replay.read_bytes()
            try:
                replay_payload = json.loads(replay_raw)
            except json.JSONDecodeError as error:
                raise CodeTaskError(f"patch replay evidence is malformed: {error}") from error
            update.update(
                {
                    "patch_replay": replay.name,
                    "patch_replay_sha256": hashlib.sha256(replay_raw).hexdigest(),
                    "patch_replay_ok": bool(replay_payload.get("ok", False)),
                }
            )
        audit = self.evidence_dir / "patch-audit.json"
        if audit.is_file():
            audit_raw = audit.read_bytes()
            try:
                audit_payload = json.loads(audit_raw)
            except json.JSONDecodeError as error:
                raise CodeTaskError(f"patch audit evidence is malformed: {error}") from error
            update.update(
                {
                    "patch_audit": audit.name,
                    "patch_audit_sha256": hashlib.sha256(audit_raw).hexdigest(),
                    "patch_audit_ok": bool(audit_payload.get("ok", False)),
                }
            )
        delivery = self.evidence_dir / "delivery-seal.json"
        if delivery.is_file():
            delivery_raw = delivery.read_bytes()
            delivery_payload = json.loads(delivery_raw)
            update.update({
                "delivery_seal": delivery.name,
                "delivery_seal_sha256": hashlib.sha256(delivery_raw).hexdigest(),
                "delivery_seal_ok": bool(delivery_payload.get("ok", False)),
            })
        self._write_manifest(update)
        return path

    def capture(self, *, exit_code: int, terminal: str) -> Path:
        """Capture tracked and untracked changes as one binary-capable patch."""
        if self.worktree is None or self.evidence_dir is None:
            raise CodeTaskError("code workspace has not been prepared")
        # Intent-to-add makes untracked files visible without changing the
        # caller's index (this index belongs only to the detached task tree).
        patch = _current_patch(self.worktree)
        patch_path = self.evidence_dir / "changes.patch"
        _atomic_write(patch_path, patch)
        status = _run_git(self.worktree, "status", "--short").stdout.decode(
            "utf-8", errors="replace"
        )
        _atomic_write(self.evidence_dir / "git-status.txt", status.encode("utf-8"))
        self._write_manifest(
            {
                "status": terminal,
                "exit_code": int(exit_code),
                "patch": patch_path.name,
                "patch_bytes": len(patch),
                "patch_sha256": hashlib.sha256(patch).hexdigest(),
                "git_status": status.splitlines(),
            }
        )
        return patch_path

    def cleanup(self) -> None:
        """Remove only the disposable worktree; evidence is never removed here."""
        if self.repository is None or self.worktree is None:
            return
        _run_git(self.repository, "worktree", "remove", "--force", str(self.worktree))
        _run_git(self.repository, "worktree", "prune")
        if self._temporary_parent is not None:
            try:
                self._temporary_parent.rmdir()
            except OSError:
                pass
        self._write_manifest({"worktree_removed": True})

    def preserve(self, *, reason: str) -> None:
        self._write_manifest({"worktree_removed": False, "preserved_reason": reason})


@dataclass(frozen=True)
class CodeRunReport:
    """Public summary produced by a ``northstar code`` orchestration."""

    run_id: str
    subtype: str
    start_commit: str
    evidence_dir: str
    patch_path: str
    worktree: str | None
    exit_code: int
    checks: tuple[dict[str, Any], ...] = ()
    verification_path: str = ""
    phase_path: str = ""
    patch_replay_path: str = ""
    patch_audit_path: str = ""
    delivery_seal_path: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and self.subtype in {"success", "success_unverified"}

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "subtype": self.subtype,
            "start_commit": self.start_commit,
            "evidence_dir": self.evidence_dir,
            "patch_path": self.patch_path,
            "worktree": self.worktree,
            "exit_code": self.exit_code,
            "checks": list(self.checks),
            "verification_path": self.verification_path,
            "phase_path": self.phase_path,
            "patch_replay_path": self.patch_replay_path,
            "patch_audit_path": self.patch_audit_path,
            "delivery_seal_path": self.delivery_seal_path,
        }
