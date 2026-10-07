"""Health check aggregator for monitoring.

Runs a registry of health checks and aggregates them into one overall
status. This is a *monitoring* primitive, not an authorization gate:
HEALTHY means "every check that ran passed", never "the system is safe".

House style: frozen dataclasses, no wall-clock (all seqs caller-supplied),
fail-closed, stdlib-only, deterministic.

Aggregation rule (fail-closed):
  - every registered check passes            -> HEALTHY
  - some check fails, all failures non-critical -> DEGRADED
  - any failing check is critical              -> UNHEALTHY
  - a check that raises is recorded as a failure, not propagated:
    a crashing probe must not crash the monitor that watches it.

Honest scope: the aggregator only sees what check_fn reports. A check
that lies healthy stays healthy. Clean verdict = "all checks passed",
never "the system is healthy".
"""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

HEALTH_CHECKER_VERSION = "health-checker.v1"
SCHEMA_PIN = "northstar.health-checker.v1"


class HealthStatus(enum.Enum):
    """Overall / per-check status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class HealthCheckError(Exception):
    """Raised for malformed registrations (programming errors), not check failures."""


def _check_fn_shape(fn: Callable) -> None:
    if not callable(fn):
        raise TypeError("check_fn must be callable")
    # Inspect without calling: accept 0 or 1 positional params (seq).
    try:
        import inspect

        params = inspect.signature(fn).parameters
        positional = [
            p
            for p in params.values()
            if p.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
            and p.default is inspect.Parameter.empty
        ]
        if len(positional) > 1:
            raise HealthCheckError(
                "check_fn must take 0 or 1 positional arguments (seq)"
            )
        if any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params.values()):
            raise HealthCheckError("check_fn must not use *args")
    except (TypeError, ValueError):
        # Builtins without a signature: allow, but only if callable.
        pass


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _digest(body: str) -> str:
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class HealthCheck:
    """One registered probe.

    check_fn(seq) -> bool | (bool, detail).
    ``critical``: a failure of a critical check -> UNHEALTHY; a failure of a
    non-critical check -> DEGRADED.
    """

    name: str
    check_fn: Callable
    critical: bool = True
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name must be a non-empty string")
        if not isinstance(self.critical, bool):
            raise TypeError("critical must be a bool")
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"schema must be {SCHEMA_PIN!r}")
        _check_fn_shape(self.check_fn)


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one check run."""

    name: str
    status: str  # HealthStatus value
    critical: bool
    seq: int
    detail: str = ""
    digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "name": self.name,
            "status": self.status,
            "critical": self.critical,
            "seq": self.seq,
            "detail": self.detail,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class HealthReport:
    """Aggregated report over all checks, in registration order."""

    overall: str  # HealthStatus value
    seq: int
    results: Tuple[CheckResult, ...]
    digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "overall": self.overall,
            "seq": self.seq,
            "results": [r.as_dict() for r in self.results],
            "digest": self.digest,
        }


def _report_digest(results: Sequence[CheckResult], seq: int) -> str:
    body = _canon(
        {
            "seq": seq,
            "results": [
                (r.name, r.status, r.critical, r.seq, r.detail) for r in results
            ],
        }
    )
    return _digest(body)


def _invoke(fn: Callable, seq: int) -> Tuple[bool, str]:
    """Call check_fn(seq-or-empty) and normalize to (healthy, detail)."""
    try:
        import inspect

        try:
            params = inspect.signature(fn).parameters
            positional = [
                p
                for p in params.values()
                if p.kind
                in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
                and p.default is inspect.Parameter.empty
            ]
            n = len(positional)
        except (TypeError, ValueError):
            n = 0
    except Exception:
        n = 0
    out = fn(seq) if n == 1 else fn()
    if isinstance(out, tuple):
        if len(out) != 2:
            raise HealthCheckError("check_fn tuple result must be (bool, detail)")
        ok, detail = out
        if not isinstance(ok, bool):
            raise HealthCheckError("check_fn first tuple element must be a bool")
        if not isinstance(detail, str):
            raise HealthCheckError("check_fn detail must be a string")
        return ok, detail
    if not isinstance(out, bool):
        raise HealthCheckError("check_fn must return bool or (bool, detail)")
    return out, ""


class HealthChecker:
    """Registry of health checks with one aggregation entry point."""

    def __init__(self) -> None:
        self._checks: List[HealthCheck] = []
        self._names: set = set()

    def register(self, check: HealthCheck, seq: int = 0) -> HealthCheck:
        if not isinstance(check, HealthCheck):
            raise TypeError("check must be a HealthCheck")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise HealthCheckError("seq must be a non-negative int")
        if check.name in self._names:
            raise HealthCheckError(f"duplicate check name: {check.name!r}")
        self._checks.append(check)
        self._names.add(check.name)
        return check

    def registered(self) -> Tuple[str, ...]:
        return tuple(c.name for c in self._checks)

    def check_all(self, seq: int) -> HealthReport:
        """Run every check and aggregate. A raising check -> failure, not crash."""
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise HealthCheckError("seq must be a non-negative int")
        results: List[CheckResult] = []
        for check in self._checks:
            try:
                ok, detail = _invoke(check.check_fn, seq)
                status = (
                    HealthStatus.HEALTHY.value if ok else HealthStatus.UNHEALTHY.value
                )
            except Exception as exc:  # noqa: BLE001 - a failing probe is a failure
                status = HealthStatus.UNHEALTHY.value
                detail = f"check raised {type(exc).__name__}"
            digest = _digest(
                _canon(
                    {"name": check.name, "status": status, "seq": seq, "detail": detail}
                )
            )
            results.append(
                CheckResult(
                    name=check.name,
                    status=status,
                    critical=check.critical,
                    seq=seq,
                    detail=detail,
                    digest=digest,
                )
            )
        tuple_results = tuple(results)
        if not tuple_results:
            overall = HealthStatus.HEALTHY.value  # nothing registered: no known failure
        elif any(
            r.status != HealthStatus.HEALTHY.value and r.critical for r in tuple_results
        ):
            overall = HealthStatus.UNHEALTHY.value
        elif any(r.status != HealthStatus.HEALTHY.value for r in tuple_results):
            overall = HealthStatus.DEGRADED.value
        else:
            overall = HealthStatus.HEALTHY.value
        return HealthReport(
            overall=overall,
            seq=seq,
            results=tuple_results,
            digest=_report_digest(tuple_results, seq),
        )

    def health_audit_event(self, report: HealthReport) -> Dict[str, Any]:
        """audit.ndjson/1-shaped record for a check_all report."""
        if not isinstance(report, HealthReport):
            raise TypeError("report must be a HealthReport")
        d = report.as_dict()
        d["audit_seq"] = report.seq
        d["kind"] = "health-check"
        return d


def health_audit_event(report: HealthReport, seq: int) -> Dict[str, Any]:
    """Standalone audit event builder (seq caller-supplied)."""
    if not isinstance(report, HealthReport):
        raise TypeError("report must be a HealthReport")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise HealthCheckError("seq must be a non-negative int")
    d = report.as_dict()
    d["audit_seq"] = seq
    d["kind"] = "health-check"
    return d


def main() -> None:
    hc = HealthChecker()
    hc.register(HealthCheck("disk", lambda seq: True))
    hc.register(HealthCheck("cache", lambda seq: (False, "hit rate 0.41"), critical=False))
    hc.register(HealthCheck("auth", lambda seq: False))
    r1 = hc.check_all(seq=1)
    assert r1.overall == HealthStatus.UNHEALTHY.value, r1.overall
    hc2 = HealthChecker()
    hc2.register(HealthCheck("disk", lambda seq: True))
    hc2.register(HealthCheck("cache", lambda seq: (False, "slow"), critical=False))
    r2 = hc2.check_all(seq=2)
    assert r2.overall == HealthStatus.DEGRADED.value, r2.overall
    print("health-checker OK: unhealthy on critical failure, degraded otherwise")


if __name__ == "__main__":
    main()
