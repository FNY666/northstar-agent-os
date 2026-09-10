"""Default-disabled OpenAI-compatible planner transport."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from planner_adapter import PlannerModelResponse

_SCHEMA = "northstar.planner-candidate.v1"
_MAX_ENDPOINT = 2_048
_MAX_ENV = 128
_MAX_ID = 128


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_ID or any(c.isspace() or c in "/\\\x00" for c in value):
        raise ValueError(f"{field} is invalid")
    return value


def _endpoint(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_ENDPOINT:
        raise ValueError("endpoint is invalid")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("endpoint must be an HTTPS URL without embedded credentials")
    return value


def _positive_float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 900:
        raise ValueError(f"{field} is invalid")
    return float(value)


@dataclass(frozen=True)
class OpenAICompatiblePlannerConfig:
    endpoint: str
    api_key_env: str
    model_id: str
    provider: str
    model_revision: str
    timeout_seconds: float = 30.0
    max_response_bytes: int = 262_144

    def __post_init__(self) -> None:
        object.__setattr__(self, "endpoint", _endpoint(self.endpoint))
        if not isinstance(self.api_key_env, str) or not 1 <= len(self.api_key_env) <= _MAX_ENV or not self.api_key_env.replace("_", "A").isalnum() or self.api_key_env[0].isdigit():
            raise ValueError("api_key_env is invalid")
        for field in ("model_id", "provider", "model_revision"):
            object.__setattr__(self, field, _id(getattr(self, field), field))
        object.__setattr__(self, "timeout_seconds", _positive_float(self.timeout_seconds, "timeout_seconds"))
        if not isinstance(self.max_response_bytes, int) or isinstance(self.max_response_bytes, bool) or not 1 <= self.max_response_bytes <= 16 * 1024 * 1024:
            raise ValueError("max_response_bytes is invalid")


class OpenAICompatiblePlannerCaller:
    """Call one configured endpoint; transport failures are never retried."""

    def __init__(self, config: OpenAICompatiblePlannerConfig, *, transport: Callable[[Request, float], bytes] | None = None):
        if not isinstance(config, OpenAICompatiblePlannerConfig):
            raise ValueError("config is invalid")
        if transport is not None and not callable(transport):
            raise ValueError("transport must be callable")
        self.config = config
        self._transport = transport or self._default_transport

    @staticmethod
    def _default_transport(request: Request, timeout: float) -> bytes:
        with urlopen(request, timeout=timeout) as response:
            return response.read()

    def _request_body(self, *, goal: str, context: dict[str, Any], repair_error: str | None) -> bytes:
        if not isinstance(goal, str) or not goal or len(goal.encode("utf-8")) > 32_000:
            raise ValueError("planner goal is invalid")
        if not isinstance(context, dict):
            raise ValueError("planner context is invalid")
        body = {
            "model": self.config.model_id,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": "Return JSON with exactly one top-level plan field. The plan must be a typed candidate; do not return commands, callables, credentials, or provider metadata."},
                {"role": "user", "content": json.dumps({"goal": goal, "context": context, "repair_error": repair_error}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))},
            ],
        }
        encoded = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > 512_000:
            raise ValueError("planner request exceeds the maximum size")
        return encoded

    def _parse_response(self, raw: bytes) -> PlannerModelResponse:
        if not isinstance(raw, bytes) or len(raw) > self.config.max_response_bytes:
            raise ValueError("planner response exceeds the maximum size")
        try:
            envelope = json.loads(raw.decode("utf-8"))
            choices = envelope["choices"]
            content = choices[0]["message"]["content"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, IndexError, TypeError) as error:
            raise ValueError("planner provider response is invalid") from error
        if not isinstance(content, str) or not content:
            raise ValueError("planner provider content is invalid")
        try:
            body = json.loads(content)
        except (json.JSONDecodeError, TypeError) as error:
            raise ValueError("planner provider content is not JSON") from error
        if not isinstance(body, dict) or set(body) != {"plan"}:
            raise ValueError("planner provider content must contain only plan")
        return PlannerModelResponse(body, self.config.model_id, self.config.provider, self.config.model_revision)

    def __call__(self, *, goal: str, context: dict[str, Any], repair_error: str | None, attempt: int) -> PlannerModelResponse:
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt <= 0:
            raise ValueError("planner attempt is invalid")
        key = os.environ.get(self.config.api_key_env)
        if not key:
            raise ValueError("planner API key is unavailable")
        request = Request(
            self.config.endpoint,
            data=self._request_body(goal=goal, context=context, repair_error=repair_error),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
            method="POST",
        )
        try:
            raw = self._transport(request, self.config.timeout_seconds)
        except Exception as error:
            raise ValueError("planner transport failed") from error
        return self._parse_response(raw)
