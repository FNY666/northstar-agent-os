"""Profiler: pprof-style CPU sampling bookkeeping (simulated).

Research note: pprof (Google) aggregates sampled stack traces into a
profile — per-function cumulative/self sample counts plus the folded-stack
("f1;f2;f3 N") representation consumed by flame-graph renderers (Brendan
Gregg's folded format). The sampling itself is the profiler's job; the
aggregation is pure bookkeeping over the samples it observed.

This module is the *aggregation* half, not a sampler:

* **Session lifecycle** — ``start(seq)`` opens a profile, ``record(stack,
  seq)`` books one host-reported sample, ``stop(seq)`` closes it with a
  frozen :class:`ProfileReport`. Start-while-running and
  record/stop-while-stopped are refused fail-closed.
* **Aggregation** — per-frame *self* counts (frame on top of the stack)
  and *cumulative* counts (frame anywhere in the stack), plus a
  :class:`Flamegraph` of folded stack lines in deterministic sorted order.
* **Digest pins** — every report pins its content with ``sha256:`` digests
  (type-tagged canonical encoding: ``"1"`` ≠ ``1`` ≠ ``b"1"``; NaN/inf and
  integral floats with magnitude > 2**53 are refused, the same JCS float-loss
  caveat documented in the batch line).
* **No wall-clock** — ordering comes from caller-supplied int ``seq``s,
  strictly increasing across mutations; a non-increasing seq is rejected.

Honest scope: this module cannot sample a real process — samples are
*host-reported* stacks, so a lying host yields a consistent profile of
lies (GIGO boundary, same as every bookkeeping module). ``self`` vs
``cumulative`` counts rank *reported* time, never ground truth; there is
no wall-clock, no stack walker, no symbolizer. Pair with real sampling
(host's job) and with the audit writer for crash recovery.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

#: Module version.
PROFILER_VERSION = "profiler.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.profiler.v1"

_ZERO_DIGEST = "sha256:" + "0" * 64

#: Guardrails.
_MAX_STACK_DEPTH = 256
_MAX_FRAME_LEN = 512


class ProfilerError(Exception):
    """Malformed input or lifecycle misuse of the profiler."""


class LifecycleError(ProfilerError):
    """Start/stop/record called in the wrong session state."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProfilerError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ProfilerError(f"{name} must be non-negative, got {value}")
    return value


def _check_frame(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise ProfilerError(f"frame must be a str, got {type(value).__name__}")
    if not value:
        raise ProfilerError("frame must be non-empty")
    if len(value) > _MAX_FRAME_LEN:
        raise ProfilerError(f"frame too long (> {_MAX_FRAME_LEN} chars)")
    return value


def _check_stack(value: Any) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise ProfilerError(f"stack must be a sequence of frames, got {type(value).__name__}")
    frames = tuple(_check_frame(f) for f in value)
    if not frames:
        raise ProfilerError("stack must contain at least one frame")
    if len(frames) > _MAX_STACK_DEPTH:
        raise ProfilerError(f"stack too deep (> {_MAX_STACK_DEPTH} frames)")
    return frames


def _canonical(value: Any) -> bytes:
    """Type-tagged canonical encoding (bool distinct from int)."""
    if isinstance(value, bool):
        return b"b:" + (b"1" if value else b"0")
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise ProfilerError("integral magnitude > 2**53 cannot be pinned safely")
        return b"i:" + str(value).encode("ascii")
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ProfilerError("NaN/inf cannot be pinned")
        if value.is_integer() and abs(value) > 2**53:
            raise ProfilerError("integral magnitude > 2**53 cannot be pinned safely")
        return b"f:" + repr(value).encode("ascii")
    if isinstance(value, str):
        return b"s:" + value.encode("utf-8")
    if isinstance(value, (tuple, list)):
        return b"l:[" + b",".join(_canonical(v) for v in value) + b"]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0])
        return b"d:{" + b",".join(_canonical(k) + b"=" + _canonical(v) for k, v in items) + b"}"
    raise ProfilerError(f"cannot pin value of type {type(value).__name__}")


def _digest_of(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class FrameStats:
    """Per-frame self/cumulative sample counts."""

    frame: str
    self_samples: int
    cumulative_samples: int
    version: str = PROFILER_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if self.self_samples < 0 or self.cumulative_samples < 0:
            raise ProfilerError("sample counts must be non-negative")
        if self.self_samples > self.cumulative_samples:
            raise ProfilerError("self_samples cannot exceed cumulative_samples")

    def record_digest(self) -> str:
        return _digest_of(
            {"frame": self.frame, "self": self.self_samples,
             "cumulative": self.cumulative_samples}
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "frame": self.frame,
            "self_samples": self.self_samples,
            "cumulative_samples": self.cumulative_samples,
            "digest": self.record_digest(),
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ProfileReport:
    """Frozen aggregation of one closed profile session."""

    session_id: str
    total_samples: int
    frame_stats: tuple[FrameStats, ...] = field(default_factory=tuple)
    seq_start: int = 0
    seq_end: int = 0
    version: str = PROFILER_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if self.total_samples < 0:
            raise ProfilerError("total_samples must be non-negative")

    def record_digest(self) -> str:
        return _digest_of(
            {
                "session_id": self.session_id,
                "total_samples": self.total_samples,
                "frames": sorted(
                    (f.frame, f.self_samples, f.cumulative_samples)
                    for f in self.frame_stats
                ),
                "seq_start": self.seq_start,
                "seq_end": self.seq_end,
            }
        )

    def top_frames(self, n: int = 10) -> tuple[FrameStats, ...]:
        """Top-*n* frames by cumulative samples, frame-name tie-break."""
        return tuple(
            sorted(self.frame_stats, key=lambda f: (-f.cumulative_samples, f.frame))[:n]
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "total_samples": self.total_samples,
            "frame_stats": [f.as_dict() for f in self.frame_stats],
            "seq_start": self.seq_start,
            "seq_end": self.seq_end,
            "digest": self.record_digest(),
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Flamegraph:
    """Folded-stack representation: ``f1;f2;f3 N`` lines, sorted."""

    session_id: str
    lines: tuple[str, ...] = field(default_factory=tuple)
    total_samples: int = 0
    version: str = PROFILER_VERSION
    schema: str = SCHEMA_PIN

    def record_digest(self) -> str:
        return _digest_of(
            {"session_id": self.session_id, "lines": list(self.lines)}
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "lines": list(self.lines),
            "total_samples": self.total_samples,
            "digest": self.record_digest(),
            "version": self.version,
            "schema": self.schema,
        }


class Profiler:
    """Simulated pprof-style sampling profiler (aggregation only)."""

    def __init__(self, session_id: str) -> None:
        if isinstance(session_id, bool) or not isinstance(session_id, str) or not session_id:
            raise ProfilerError("session_id must be a non-empty str")
        self._session_id = session_id
        self._lock = threading.RLock()
        self._running = False
        self._stack_counts: dict[tuple[str, ...], int] = {}
        self._last_folded: dict[tuple[str, ...], int] = {}
        self._last_seq = -1
        self._seq_start = 0
        self._reports: list[ProfileReport] = []

    def _advance(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise ProfilerError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def start(self, seq: int) -> None:
        """Open a profiling session."""
        with self._lock:
            seq = self._advance(seq)
            if self._running:
                raise LifecycleError("profiler already running")
            self._running = True
            self._stack_counts = {}
            self._seq_start = seq

    def record(self, stack: Iterable[str], seq: int) -> None:
        """Book one host-reported sample (stack: root-first, leaf-last)."""
        with self._lock:
            seq = self._advance(seq)
            if not self._running:
                raise LifecycleError("profiler not running: call start() first")
            frames = _check_stack(stack)
            self._stack_counts[frames] = self._stack_counts.get(frames, 0) + 1

    def stop(self, seq: int) -> ProfileReport:
        """Close the session; return the frozen aggregation report."""
        with self._lock:
            seq = self._advance(seq)
            if not self._running:
                raise LifecycleError("profiler not running")
            self._running = False
            total = sum(self._stack_counts.values())
            self_samples: dict[str, int] = {}
            cumulative: dict[str, int] = {}
            for stack, count in self._stack_counts.items():
                leaf = stack[-1]
                self_samples[leaf] = self_samples.get(leaf, 0) + count
                for frame in set(stack):
                    cumulative[frame] = cumulative.get(frame, 0) + count
            stats = tuple(
                FrameStats(frame=f, self_samples=self_samples.get(f, 0),
                           cumulative_samples=cumulative[f])
                for f in sorted(cumulative)
            )
            report = ProfileReport(
                session_id=self._session_id,
                total_samples=total,
                frame_stats=stats,
                seq_start=self._seq_start,
                seq_end=seq,
            )
            self._reports.append(report)
            self._last_folded = dict(self._stack_counts)
            self._stack_counts = {}
            return report

    def flamegraph(self, report: Optional[ProfileReport] = None) -> Flamegraph:
        """Folded-stack lines for the most recently closed session.

        Stacks are only retained for the most recently closed session;
        asking for any other report is refused fail-closed rather than
        fabricating folded lines. An explicit ``report`` must therefore
        be this profiler's latest closed report (digest-matched).
        """
        with self._lock:
            if not self._reports:
                raise LifecycleError("no closed profile to render")
            latest = self._reports[-1]
            if report is not None:
                if not isinstance(report, ProfileReport):
                    raise ProfilerError(
                        f"report must be a ProfileReport, got {type(report).__name__}"
                    )
                if not hmac.compare_digest(
                    report.record_digest(), latest.record_digest()
                ):
                    raise ProfilerError(
                        "folded stacks are retained only for the most recently "
                        "closed session"
                    )
            lines = tuple(
                ";".join(stack) + f" {count}"
                for stack, count in sorted(self._last_folded.items())
                if count > 0
            )
            return Flamegraph(
                session_id=latest.session_id,
                lines=lines,
                total_samples=latest.total_samples,
            )

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def sample_count(self) -> int:
        """Samples booked in the currently open session."""
        with self._lock:
            return sum(self._stack_counts.values())

    def reports(self) -> tuple[ProfileReport, ...]:
        with self._lock:
            return tuple(self._reports)


def profiler_audit_event(kind: str, seq: int, **detail: Any) -> dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for a profiler event.

    Fixed kind vocabulary: ``profile-started`` / ``sample-recorded`` /
    ``profile-stopped`` / ``flamegraph-built`` / ``rejected``. Raw stacks
    are never emitted — only session id, counts, and digest pins.
    """
    kinds = ("profile-started", "sample-recorded", "profile-stopped",
             "flamegraph-built", "rejected")
    if kind not in kinds:
        raise ProfilerError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    return {
        "event": f"profiler.{kind}",
        "seq": seq,
        "detail": dict(detail),
        "profiler_version": PROFILER_VERSION,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    """Self-check: open, record, stop, render a flamegraph."""
    p = Profiler("self-check")
    assert not p.is_running()
    p.start(1)
    p.record(["main", "serve", "handle"], 2)
    p.record(["main", "serve", "handle"], 3)
    p.record(["main", "serve", "encode"], 4)
    assert p.sample_count() == 3
    report = p.stop(5)
    assert report.total_samples == 3
    by_frame = {f.frame: f for f in report.frame_stats}
    assert by_frame["handle"].self_samples == 2
    assert by_frame["serve"].cumulative_samples == 3
    assert by_frame["serve"].self_samples == 0
    assert by_frame["main"].cumulative_samples == 3
    fg = p.flamegraph(report=report)
    assert fg.lines == ("main;serve;encode 1", "main;serve;handle 2")
    assert hmac.compare_digest(fg.record_digest(), fg.record_digest())
    assert report.top_frames(1)[0].frame == "main"
    try:
        p.record(["x"], 6)
    except LifecycleError:
        pass
    else:
        raise AssertionError("record after stop must fail")
    print("profiler OK: start, record, stop, flamegraph, refusals")


if __name__ == "__main__":
    main()


__all__ = [
    "PROFILER_VERSION",
    "SCHEMA_PIN",
    "ProfilerError",
    "LifecycleError",
    "FrameStats",
    "ProfileReport",
    "Flamegraph",
    "Profiler",
    "profiler_audit_event",
    "main",
]
