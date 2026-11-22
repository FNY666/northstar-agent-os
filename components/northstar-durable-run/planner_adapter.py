"""Provider-neutral, fail-closed boundary for model-generated plans."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable

from agent_loop import AgentLoop, AgentPlan

_SCHEMA = "northstar.planner-candidate.v1"
_DIGEST_PREFIX = "sha256:"
_MAX_ID = 128
_MAX_GOAL_BYTES = 32_000
_MAX_CONTEXT_BYTES = 128_000
_MAX_OUTPUT_BYTES = 256_000
_MAX_ATTEMPTS = 2
_FORBIDDEN_KEYS = {
    "callable", "command", "commands", "executable", "function", "functions",
    "shell", "shell_command", "raw_command", "python", "code", "script",
    "credential", "credentials", "secret", "secrets", "token", "tokens",
}
_ID_RE = re.compile(r"^[^\s/\\\x00]+$")
# Host-declared model names may carry a gateway namespace (openrouter uses
# vendor/model); they are data, never paths, so the stricter rule stays for
# identity fields such as provider and model_revision.
_MODEL_ID_RE = re.compile(r"^[^\s\\\x00]+$")


class PlannerModelCallFailed(ValueError):
    """A planner transport/provider call failed with safe bounded detail.

    The detail is produced only by a trusted host caller after it has removed
    credentials and bounded provider text. Arbitrary model-caller exceptions
    are converted to the generic form by ``TypedPlannerAdapter``.
    """

    def __init__(self, detail: str | None = None):
        if detail is not None:
            if not isinstance(detail, str):
                detail = ""
            # Redact before truncating: a credential that straddles the cut
            # would otherwise leave an unmatched prefix behind.
            detail = _redact_secrets(" ".join(detail.split()))[:400]
        self.detail = detail or None
        message = "planner model call failed"
        if self.detail:
            message += f": {self.detail}"
        super().__init__(message)



def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("planner value is not canonical JSON") from error


def _digest(value: Any) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(_canonical(value)).hexdigest()


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_ID or not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _model_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_ID or not _MODEL_ID_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _digest_field(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith(_DIGEST_PREFIX) or any(c not in "0123456789abcdef" for c in value[7:]):
        raise ValueError(f"{field} is invalid")
    return value


def _reject_forbidden(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("planner output contains a non-string key")
            if key.lower() in _FORBIDDEN_KEYS:
                raise ValueError("planner output contains a forbidden execution field")
            _reject_forbidden(child)
    elif isinstance(value, list):
        for child in value:
            _reject_forbidden(child)


def _decode(value: Any, *, max_bytes: int) -> dict[str, Any]:
    if isinstance(value, str):
        raw = value.encode("utf-8")
        if len(raw) > max_bytes:
            raise ValueError("planner output exceeds the maximum size")
        try:
            value = json.loads(value)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("planner output is not valid JSON") from error
    else:
        raw = _canonical(value)
        if len(raw) > max_bytes:
            raise ValueError("planner output exceeds the maximum size")
    if not isinstance(value, dict):
        raise ValueError("planner output must be an object")
    _reject_forbidden(value)
    return value


@dataclass(frozen=True)
class PlannerModelResponse:
    content: str | dict[str, Any]
    model_id: str
    provider: str
    model_revision: str

    def __post_init__(self) -> None:
        _model_id(self.model_id, "model_id")
        _id(self.provider, "provider")
        _id(self.model_revision, "model_revision")
        if not isinstance(self.content, (str, dict)):
            raise ValueError("planner model content is invalid")


@dataclass(frozen=True)
class PlannerCandidate:
    plan: AgentPlan
    model_id: str
    provider: str
    model_revision: str
    output_digest: str

    @classmethod
    def from_value(cls, value: Any, *, max_bytes: int = _MAX_OUTPUT_BYTES) -> "PlannerCandidate":
        value = _decode(value, max_bytes=max_bytes)
        fields = {"schema_version", "plan", "model_id", "provider", "model_revision", "output_digest"}
        legacy_fields = fields - {"output_digest"}
        if set(value) not in (fields, legacy_fields):
            raise ValueError("planner candidate has unknown or missing fields")
        if value["schema_version"] != _SCHEMA:
            raise ValueError("planner candidate schema is invalid")
        plan = AgentPlan.from_dict(value["plan"])
        model_id = _model_id(value["model_id"], "model_id")
        provider = _id(value["provider"], "provider")
        model_revision = _id(value["model_revision"], "model_revision")
        unsigned = {
            "schema_version": _SCHEMA,
            "plan": plan.to_dict(),
            "model_id": model_id,
            "provider": provider,
            "model_revision": model_revision,
        }
        output_digest = _digest(unsigned)
        if "output_digest" in value and _digest_field(value["output_digest"], "output_digest") != output_digest:
            raise ValueError("planner candidate digest does not match")
        return cls(plan, model_id, provider, model_revision, output_digest)


@dataclass(frozen=True)
class PlannerResult:
    candidate: AgentPlan
    candidate_digest: str
    model_id: str
    provider: str
    model_revision: str
    attempts: int




_SECRET_SHAPE = re.compile(
    r"\b(?:sk|pk|ghp|gho|xox[a-z])[-_][A-Za-z0-9_-]{8,}\b"
)
_KEY_ENV_NAMES = ("KAKOUAI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY")


def _redact_secrets(text: str) -> str:
    """Remove credential-shaped text before a failure reason is reported.

    Two layers, because shapes are not a guarantee:

    1. Exact value replacement for the key environment variables this codebase
       reads.  This works whatever the provider's key format is (a bootstrap
       token, a 67-char opaque string, anything), and cannot false-positive.
    2. A shape heuristic as defence in depth for keys not in the environment.

    Neither layer is a security boundary on its own; the real boundary is that
    only ``ValueError`` messages are preserved and they are capped at 400
    characters.
    """
    import os
    for name in _KEY_ENV_NAMES:
        value = os.environ.get(name) or ""
        if len(value) >= 8:
            text = text.replace(value, "<redacted>")
    return _SECRET_SHAPE.sub("<redacted>", text)


def bounded_error_detail(error: BaseException) -> str | None:
    """Preserve a short, host-sanitized reason for a ValueError-shaped failure.

    Only ``ValueError`` messages are preserved. That is an *assumption this
    module maintains*, not a property the code guarantees: the raise sites
    audited today (planner config, request/response shape, plan admission,
    governed dispatch) are host-authored fixed text, but a future
    ``ValueError`` that interpolates provider or model output would put that
    text in a report. The two redaction layers in ``_redact_secrets`` are the
    fallback for exactly that case, and a new raise site must be checked
    before it interpolates untrusted text. Other exception types stay opaque
    on purpose.

    This is the single shared implementation for both consumers
    (``agent_driver`` reports it as ``error_detail``; ``planner_adapter``
    feeds it back as ``repair_error``). Merged in R23 from the previously
    duplicated R20/R22 copies.
    """
    if not isinstance(error, ValueError):
        return None
    text = "".join(ch if (ch.isprintable() or ch == " ") else " " for ch in str(error))
    text = " ".join(text.split())
    text = _redact_secrets(text)
    return text[:400] or None


class TypedPlannerAdapter:
    """Turn untrusted model output into an admitted, non-executing plan."""

    def __init__(self, model_caller: Callable[..., Any], *, max_output_bytes: int = _MAX_OUTPUT_BYTES, max_attempts: int = _MAX_ATTEMPTS):
        if not callable(model_caller):
            raise ValueError("model_caller must be callable")
        if not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool) or not 1 <= max_output_bytes <= _MAX_OUTPUT_BYTES:
            raise ValueError("max_output_bytes is invalid")
        if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or not 1 <= max_attempts <= _MAX_ATTEMPTS:
            raise ValueError("max_attempts is invalid")
        self.model_caller = model_caller
        self.max_output_bytes = max_output_bytes
        self.max_attempts = max_attempts

    def generate(self, goal: str, *, context: dict[str, Any], loop: AgentLoop, current_policy_revision: str, owner_id: str, now: int) -> PlannerResult:
        if not isinstance(goal, str) or not goal or len(goal.encode("utf-8")) > _MAX_GOAL_BYTES:
            raise ValueError("goal is invalid")
        if not isinstance(context, dict) or len(_canonical(context)) > _MAX_CONTEXT_BYTES:
            raise ValueError("planner context is invalid")
        if not isinstance(loop, AgentLoop):
            raise ValueError("loop is invalid")
        _id(owner_id, "owner_id")
        if not isinstance(now, int) or isinstance(now, bool) or now <= 0:
            raise ValueError("now is invalid")
        previous_error: str | None = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                response = self.model_caller(
                    goal=goal,
                    context=context,
                    repair_error=previous_error,
                    attempt=attempt,
                )
            except Exception as error:
                if isinstance(error, PlannerModelCallFailed):
                    raise
                raise PlannerModelCallFailed() from error
            if not isinstance(response, PlannerModelResponse):
                raise ValueError("planner model caller must return PlannerModelResponse")
            try:
                candidate_value = response.content
                candidate = PlannerCandidate.from_value(
                    {
                        "schema_version": _SCHEMA,
                        "plan": _decode(candidate_value, max_bytes=self.max_output_bytes).get("plan", candidate_value),
                        "model_id": response.model_id,
                        "provider": response.provider,
                        "model_revision": response.model_revision,
                    },
                    max_bytes=self.max_output_bytes,
                )
            except Exception as error:
                # R22: keep the validator's own message (bounded, redacted) so
                # the next attempt can actually fix the named field, and the
                # final report can say which one failed -- instead of a bare
                # "ValueError" that forces a blind retry.
                previous_error = bounded_error_detail(error)
                if attempt == self.max_attempts:
                    raise PlannerModelCallFailed(previous_error) from error
                continue
            try:
                admitted = loop.admit(
                    candidate.plan, current_policy_revision=current_policy_revision
                )
            except ValueError as error:
                previous_error = bounded_error_detail(error)
                if attempt == self.max_attempts:
                    raise PlannerModelCallFailed(previous_error) from error
                continue
            return PlannerResult(
                candidate=admitted,
                candidate_digest=candidate.output_digest,
                model_id=candidate.model_id,
                provider=candidate.provider,
                model_revision=candidate.model_revision,
                attempts=attempt,
            )
        raise ValueError("planner output was not admitted")
