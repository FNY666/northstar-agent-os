"""SDK generation interface (OpenAPI Generator shaped, simulated).

Research motivation: OpenAPI Generator turns an API contract into
multi-language SDKs — spec ingestion, per-language template rendering, and
package-registry publication. This module implements that shape as a
deterministic, single-host ledger:

* **Register** — :meth:`SDKGeneration.register_spec` books an API contract
  by ``sha256:`` digest only (spec bytes never cross the module boundary).
* **Generate** — :meth:`SDKGeneration.generate` renders a deterministic SDK
  bundle from a registered spec into a pinned language vocabulary
  (``python``/``typescript``/``go``/``java``/``rust``/``kotlin``/``swift``/
  ``php``/``ruby``/``csharp``). The bundle is a frozen :class:`SDKBuild`
  (``sdk-N`` ids) whose digest pin covers the exact generated text;
  :meth:`SDKBuild.verify` re-derives it.
* **Publish** — :meth:`SDKGeneration.publish` books a release of a build to a
  pinned registry vocabulary (``pypi``/``npm``/``crates``/``maven``/
  ``nuget``/``rubygems``/``packagist``); one active publication per
  (build, registry), terminal until withdrawn.
* **Version** — :meth:`SDKGeneration.version` mints a new build from an
  existing one with a semver ``major``/``minor``/``patch`` bump.

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing on mutations — no wall-clock, no RNG), RLock-guarded,
fail-closed taxonomy under :class:`SDKGenerationError`, stdlib-only,
type-tagged canonical digest encoding (bool != int; NaN/inf and
|n| >= 2**53 refused at pin time — the batch-5 JCS float-loss caveat),
audit events shaped for ``audit.ndjson/1``, ``main()`` self-check.

Honest scope: this is *release bookkeeping and template rendering*, not a
real code generator or package publisher. Rendered SDKs are fixed text
templates over the registered spec digest — they do not compile, they do
not guarantee the spec is implementable, and a ``published=True`` record
means "the host reported this publication", never that a registry accepted
it. A lying digest gets a consistent ledger of lies (GIGO, same boundary as
every other bookkeeping module). Production SDK release needs a real
generator (openapi-generator) plus registry credentials and provenance
attestation (see ``provenance_attestor``, ``artifact_publisher``).

Version pin: sdk-generation.v1
Schema pin: northstar.sdk-generation.v1
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return "sha256:" + hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Module version pin.
SDK_GENERATION_VERSION = "sdk-generation.v1"

#: Schema pin for records produced by this module.
SDK_GENERATION_SCHEMA = "northstar.sdk-generation.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned target-language vocabulary (openapi-generator shaped).
LANGUAGES = frozenset(
    {
        "python",
        "typescript",
        "go",
        "java",
        "rust",
        "kotlin",
        "swift",
        "php",
        "ruby",
        "csharp",
    }
)

#: Pinned package-registry vocabulary.
REGISTRIES = frozenset(
    {"pypi", "npm", "crates", "maven", "nuget", "rubygems", "packagist"}
)

#: Pinned semver bump vocabulary.
BUMPS = frozenset({"major", "minor", "patch"})

#: Language -> default package manager command (documentation, never executed).
PACKAGE_MANAGERS = {
    "python": "pip",
    "typescript": "npm",
    "go": "go",
    "java": "maven",
    "rust": "cargo",
    "kotlin": "gradle",
    "swift": "swiftpm",
    "php": "composer",
    "ruby": "gem",
    "csharp": "nuget",
}

#: Audit event kinds.
_AUDIT_KINDS = (
    "spec-registered",
    "sdk-generated",
    "sdk-published",
    "sdk-withdrawn",
    "version-bumped",
    "rejected",
)

#: Guardrails.
MAX_ID_LEN = 128
MAX_NAME_LEN = 128
MAX_SPECS = 65536
MAX_BUILDS = 65536

_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SDKGenerationError(ValueError):
    """Base fail-closed SDK-generation error."""


class BadSpecError(SDKGenerationError):
    """Spec registration input refused."""


class DuplicateSpecError(SDKGenerationError):
    """Spec id already registered."""


class UnknownSpecError(SDKGenerationError):
    """Spec id not registered."""


class BadBuildError(SDKGenerationError):
    """SDK build input refused."""


class UnknownBuildError(SDKGenerationError):
    """Build id unknown."""


class BadVersionError(SDKGenerationError):
    """Version string or bump refused."""


class BadPublishError(SDKGenerationError):
    """Publish/withdraw input refused."""


class AlreadyPublishedError(SDKGenerationError):
    """Build already published to this registry (active)."""


class NotPublishedError(SDKGenerationError):
    """No active publication to withdraw."""


class SeqOrderError(SDKGenerationError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise SDKGenerationError(
            f"{name} must match [A-Za-z0-9][A-Za-z0-9._-]{{0,127}}"
        )
    return value


def _check_name(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise SDKGenerationError(f"{name} must be a string")
    text = value.strip()
    if not text or len(text) > MAX_NAME_LEN:
        raise SDKGenerationError(f"{name} must be 1..{MAX_NAME_LEN} chars")
    return text


def _check_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.match(value):
        raise SDKGenerationError(
            f"{name} must be 'sha256:' + 64 lowercase hex"
        )
    return value


def _parse_semver(value: Any, name: str) -> Tuple[int, int, int, str]:
    if not isinstance(value, str):
        raise BadVersionError(f"{name} must be a string")
    match = _SEMVER_RE.match(value.strip())
    if not match:
        raise BadVersionError(f"{name} is not semver: {value!r}")
    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    suffix = (match.group(4) or "") + ("+" + match.group(5) if match.group(5) else "")
    return major, minor, patch, suffix


def _bump_semver(version: str, bump: str) -> str:
    major, minor, patch, _suffix = _parse_semver(version, "version")
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([SDK_GENERATION_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SpecRecord:
    """One registered API contract (booked by digest only)."""

    spec_id: str
    spec_digest: str
    operation_count: int
    seq: int
    digest: str
    schema: str = SDK_GENERATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "spec",
            self.spec_id,
            self.spec_digest,
            self.operation_count,
            self.seq,
        )


@dataclass(frozen=True)
class SDKBuild:
    """One rendered SDK bundle (frozen, digest covers generated text)."""

    build_id: str
    sdk_name: str
    language: str
    sdk_version: str
    spec_id: str
    spec_digest: str
    bundle_text: str
    prev_build_id: str
    seq: int
    digest: str
    schema: str = SDK_GENERATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "build",
            self.build_id,
            self.sdk_name,
            self.language,
            self.sdk_version,
            self.spec_id,
            self.spec_digest,
            self.bundle_text,
            self.prev_build_id,
            self.seq,
        )


@dataclass(frozen=True)
class PublishRecord:
    """One registry publication (frozen, terminal until withdrawn)."""

    publish_id: str
    build_id: str
    registry: str
    sdk_version: str
    active: bool
    seq: int
    digest: str
    schema: str = SDK_GENERATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "publish",
            self.publish_id,
            self.build_id,
            self.registry,
            self.sdk_version,
            self.active,
            self.seq,
        )


@dataclass(frozen=True)
class WithdrawRecord:
    """One publication withdrawal (terminal for that publication)."""

    publish_id: str
    reason: str
    seq: int
    digest: str
    schema: str = SDK_GENERATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "withdraw", self.publish_id, self.reason, self.seq
        )


@dataclass(frozen=True)
class VersionBumpRecord:
    """One semver bump linking parent build to child build."""

    bump_id: str
    parent_build_id: str
    child_build_id: str
    bump: str
    from_version: str
    to_version: str
    seq: int
    digest: str
    schema: str = SDK_GENERATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "bump",
            self.bump_id,
            self.parent_build_id,
            self.child_build_id,
            self.bump,
            self.from_version,
            self.to_version,
            self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def sdk_generation_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the sdk-generation module."""
    if kind not in _AUDIT_KINDS:
        raise SDKGenerationError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise SDKGenerationError("detail must be a mapping")
    # Spec bytes, bundle text, and registry credentials never cross the
    # audit boundary; ids + digest pins only.
    banned = {"spec_bytes", "bundle_text", "credentials", "token"}
    if any(k in detail for k in banned):
        raise SDKGenerationError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": SDK_GENERATION_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# Deterministic bundle renderer
# ---------------------------------------------------------------------------


def _render_bundle(
    sdk_name: str,
    language: str,
    sdk_version: str,
    spec_digest: str,
    operation_count: int,
) -> str:
    """Render the deterministic simulated SDK bundle text."""
    manager = PACKAGE_MANAGERS[language]
    lines = [
        f"# {sdk_name} {sdk_version} ({language})",
        f"# generated by {SDK_GENERATION_VERSION}; package manager: {manager}",
        f"# spec: {spec_digest}",
        f"# operations: {operation_count}",
        "",
        "# NOTE: simulated template — does not compile, does not type-check.",
        "# Pair with a real generator (openapi-generator) for production use.",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class SDKGeneration:
    """Deterministic SDK generation/publication/version ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic logical
    time); no wall-clock is read anywhere. Failed mutations consume their
    seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._specs: Dict[str, SpecRecord] = {}
        self._builds: Dict[str, SDKBuild] = {}
        self._publishes: Dict[str, PublishRecord] = {}
        self._withdrawals: Dict[str, WithdrawRecord] = {}
        self._bumps: Dict[str, VersionBumpRecord] = {}
        self._active_pub: Dict[Tuple[str, str], str] = {}
        self._audit: List[Dict[str, Any]] = []
        self._next_build = 0
        self._next_publish = 0
        self._next_bump = 0

    # -- internals ------------------------------------------------------

    def _consume_seq(self, seq: int) -> None:
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last {self._last_seq})"
            )
        self._last_seq = seq

    def _reject(self, seq: int, reason: str) -> None:
        self._audit.append(
            sdk_generation_audit_event(
                "rejected", {"reason": reason}, seq
            )
        )

    def _fail(self, seq: int, exc: SDKGenerationError, reason: str) -> None:
        # Failed mutations consume their seq and book a rejected audit row.
        self._audit.append(
            sdk_generation_audit_event("rejected", {"reason": reason}, seq)
        )
        raise exc

    # -- spec -----------------------------------------------------------

    def register_spec(
        self, spec_id: str, spec_digest: str, operation_count: int, seq: int
    ) -> SpecRecord:
        """Book an API contract by digest (spec bytes never stored)."""
        with self._lock:
            _check_seq(seq, "seq")
            try:
                _check_id(spec_id, "spec_id")
                _check_digest(spec_digest, "spec_digest")
                if (
                    isinstance(operation_count, bool)
                    or not isinstance(operation_count, int)
                    or operation_count < 0
                    or operation_count > 100000
                ):
                    raise BadSpecError(
                        "operation_count must be an int in 0..100000"
                    )
                if len(self._specs) >= MAX_SPECS:
                    raise BadSpecError("spec registry full")
                self._consume_seq(seq)
                if spec_id in self._specs:
                    raise DuplicateSpecError(f"spec exists: {spec_id!r}")
                record = SpecRecord(
                    spec_id=spec_id,
                    spec_digest=spec_digest,
                    operation_count=operation_count,
                    seq=seq,
                    digest=_pin(
                        "spec", spec_id, spec_digest, operation_count, seq
                    ),
                )
            except SDKGenerationError as exc:
                self._fail(seq, exc, f"register_spec: {exc}")
            self._audit.append(
                sdk_generation_audit_event(
                    "spec-registered",
                    {
                        "spec_id": spec_id,
                        "spec_digest": spec_digest,
                        "operation_count": operation_count,
                    },
                    seq,
                )
            )
            self._specs[spec_id] = record
            return record

    # -- generate -------------------------------------------------------

    def generate(
        self,
        spec_id: str,
        language: str,
        sdk_name: str,
        sdk_version: str,
        seq: int,
    ) -> SDKBuild:
        """Render a deterministic SDK bundle from a registered spec."""
        with self._lock:
            _check_seq(seq, "seq")
            try:
                _check_id(spec_id, "spec_id")
                if not isinstance(language, str) or language not in LANGUAGES:
                    raise BadBuildError(
                        f"language must be one of {sorted(LANGUAGES)}"
                    )
                _check_name(sdk_name, "sdk_name")
                _parse_semver(sdk_version, "sdk_version")
                if spec_id not in self._specs:
                    raise UnknownSpecError(f"unknown spec: {spec_id!r}")
                if len(self._builds) >= MAX_BUILDS:
                    raise BadBuildError("build registry full")
                self._consume_seq(seq)
                spec = self._specs[spec_id]
                self._next_build += 1
                build_id = f"sdk-{self._next_build}"
                bundle_text = _render_bundle(
                    sdk_name.strip(),
                    language,
                    sdk_version.strip(),
                    spec.spec_digest,
                    spec.operation_count,
                )
                build = SDKBuild(
                    build_id=build_id,
                    sdk_name=sdk_name.strip(),
                    language=language,
                    sdk_version=sdk_version.strip(),
                    spec_id=spec_id,
                    spec_digest=spec.spec_digest,
                    bundle_text=bundle_text,
                    prev_build_id="",
                    seq=seq,
                    digest=_pin(
                        "build",
                        build_id,
                        sdk_name.strip(),
                        language,
                        sdk_version.strip(),
                        spec_id,
                        spec.spec_digest,
                        bundle_text,
                        "",
                        seq,
                    ),
                )
            except SDKGenerationError as exc:
                self._fail(seq, exc, f"generate: {exc}")
            self._audit.append(
                sdk_generation_audit_event(
                    "sdk-generated",
                    {
                        "build_id": build_id,
                        "spec_id": spec_id,
                        "language": language,
                        "sdk_version": sdk_version,
                        "build_digest": build.digest,
                    },
                    seq,
                )
            )
            self._builds[build_id] = build
            return build

    # -- publish --------------------------------------------------------

    def publish(self, build_id: str, registry: str, seq: int) -> PublishRecord:
        """Book a build's release to a package registry (terminal)."""
        with self._lock:
            _check_seq(seq, "seq")
            try:
                _check_id(build_id, "build_id")
                if not isinstance(registry, str) or registry not in REGISTRIES:
                    raise BadPublishError(
                        f"registry must be one of {sorted(REGISTRIES)}"
                    )
                if build_id not in self._builds:
                    raise UnknownBuildError(f"unknown build: {build_id!r}")
                self._consume_seq(seq)
                key = (build_id, registry)
                if key in self._active_pub:
                    raise AlreadyPublishedError(
                        f"build {build_id!r} already published to {registry!r}"
                    )
                build = self._builds[build_id]
                self._next_publish += 1
                publish_id = f"pub-{self._next_publish}"
                record = PublishRecord(
                    publish_id=publish_id,
                    build_id=build_id,
                    registry=registry,
                    sdk_version=build.sdk_version,
                    active=True,
                    seq=seq,
                    digest=_pin(
                        "publish",
                        publish_id,
                        build_id,
                        registry,
                        build.sdk_version,
                        True,
                        seq,
                    ),
                )
            except SDKGenerationError as exc:
                self._fail(seq, exc, f"publish: {exc}")
            self._audit.append(
                sdk_generation_audit_event(
                    "sdk-published",
                    {
                        "publish_id": publish_id,
                        "build_id": build_id,
                        "registry": registry,
                        "sdk_version": build.sdk_version,
                    },
                    seq,
                )
            )
            self._publishes[publish_id] = record
            self._active_pub[key] = publish_id
            return record

    def withdraw(self, publish_id: str, seq: int, reason: str = "") -> WithdrawRecord:
        """Withdraw an active publication (terminal for that publication)."""
        with self._lock:
            _check_seq(seq, "seq")
            try:
                _check_id(publish_id, "publish_id")
                if not isinstance(reason, str) or len(reason) > 256:
                    raise BadPublishError("reason must be a string <= 256 chars")
                if publish_id not in self._publishes:
                    raise UnknownBuildError(f"unknown publication: {publish_id!r}")
                self._consume_seq(seq)
                pub = self._publishes[publish_id]
                if not pub.active:
                    raise NotPublishedError(
                        f"publication {publish_id!r} already withdrawn"
                    )
                record = WithdrawRecord(
                    publish_id=publish_id,
                    reason=reason,
                    seq=seq,
                    digest=_pin("withdraw", publish_id, reason, seq),
                )
            except SDKGenerationError as exc:
                self._fail(seq, exc, f"withdraw: {exc}")
            # Mark the publication inactive (replace frozen record).
            retired = PublishRecord(
                publish_id=pub.publish_id,
                build_id=pub.build_id,
                registry=pub.registry,
                sdk_version=pub.sdk_version,
                active=False,
                seq=pub.seq,
                digest=pub.digest,
            )
            self._publishes[publish_id] = retired
            self._active_pub.pop((pub.build_id, pub.registry), None)
            self._audit.append(
                sdk_generation_audit_event(
                    "sdk-withdrawn",
                    {"publish_id": publish_id, "reason": reason},
                    seq,
                )
            )
            self._withdrawals[publish_id] = record
            return record

    # -- version --------------------------------------------------------

    def version(self, build_id: str, bump: str, seq: int) -> SDKBuild:
        """Mint a new build from an existing one with a semver bump."""
        with self._lock:
            _check_seq(seq, "seq")
            try:
                _check_id(build_id, "build_id")
                if not isinstance(bump, str) or bump not in BUMPS:
                    raise BadVersionError(
                        f"bump must be one of {sorted(BUMPS)}"
                    )
                if build_id not in self._builds:
                    raise UnknownBuildError(f"unknown build: {build_id!r}")
                if len(self._builds) >= MAX_BUILDS:
                    raise BadBuildError("build registry full")
                self._consume_seq(seq)
                parent = self._builds[build_id]
                new_version = _bump_semver(parent.sdk_version, bump)
                self._next_build += 1
                child_id = f"sdk-{self._next_build}"
                bundle_text = _render_bundle(
                    parent.sdk_name,
                    parent.language,
                    new_version,
                    parent.spec_digest,
                    self._specs[parent.spec_id].operation_count,
                )
                child = SDKBuild(
                    build_id=child_id,
                    sdk_name=parent.sdk_name,
                    language=parent.language,
                    sdk_version=new_version,
                    spec_id=parent.spec_id,
                    spec_digest=parent.spec_digest,
                    bundle_text=bundle_text,
                    prev_build_id=build_id,
                    seq=seq,
                    digest=_pin(
                        "build",
                        child_id,
                        parent.sdk_name,
                        parent.language,
                        new_version,
                        parent.spec_id,
                        parent.spec_digest,
                        bundle_text,
                        build_id,
                        seq,
                    ),
                )
                self._next_bump += 1
                bump_id = f"bump-{self._next_bump}"
                bump_record = VersionBumpRecord(
                    bump_id=bump_id,
                    parent_build_id=build_id,
                    child_build_id=child_id,
                    bump=bump,
                    from_version=parent.sdk_version,
                    to_version=new_version,
                    seq=seq,
                    digest=_pin(
                        "bump",
                        bump_id,
                        build_id,
                        child_id,
                        bump,
                        parent.sdk_version,
                        new_version,
                        seq,
                    ),
                )
            except SDKGenerationError as exc:
                self._fail(seq, exc, f"version: {exc}")
            self._audit.append(
                sdk_generation_audit_event(
                    "version-bumped",
                    {
                        "bump_id": bump_id,
                        "parent_build_id": build_id,
                        "child_build_id": child_id,
                        "bump": bump,
                        "from_version": parent.sdk_version,
                        "to_version": new_version,
                    },
                    seq,
                )
            )
            self._builds[child_id] = child
            self._bumps[bump_id] = bump_record
            return child

    # -- views ----------------------------------------------------------

    def spec_record(self, spec_id: str) -> SpecRecord:
        """Pure lookup of a spec record."""
        with self._lock:
            _check_id(spec_id, "spec_id")
            if spec_id not in self._specs:
                raise UnknownSpecError(f"unknown spec: {spec_id!r}")
            return self._specs[spec_id]

    def build_record(self, build_id: str) -> SDKBuild:
        """Pure lookup of a build record."""
        with self._lock:
            _check_id(build_id, "build_id")
            if build_id not in self._builds:
                raise UnknownBuildError(f"unknown build: {build_id!r}")
            return self._builds[build_id]

    def publish_record(self, publish_id: str) -> PublishRecord:
        """Pure lookup of a publication record."""
        with self._lock:
            _check_id(publish_id, "publish_id")
            if publish_id not in self._publishes:
                raise UnknownBuildError(f"unknown publication: {publish_id!r}")
            return self._publishes[publish_id]

    def active_publication(
        self, build_id: str, registry: str
    ) -> Optional[PublishRecord]:
        """Pure lookup of the active publication for (build, registry)."""
        with self._lock:
            _check_id(build_id, "build_id")
            publish_id = self._active_pub.get((build_id, registry))
            return self._publishes.get(publish_id) if publish_id else None

    def builds_for_spec(self, spec_id: str) -> List[SDKBuild]:
        """Pure lookup of all builds rendered from a spec."""
        with self._lock:
            _check_id(spec_id, "spec_id")
            return [b for b in self._builds.values() if b.spec_id == spec_id]

    def audit_log(self) -> List[Dict[str, Any]]:
        """Pure view of the audit rows booked so far."""
        with self._lock:
            return list(self._audit)


# ---------------------------------------------------------------------------
# main() self-check
# ---------------------------------------------------------------------------


def main() -> None:
    gen = SDKGeneration()
    spec = gen.register_spec(
        "petstore", "sha256:" + "ab" * 32, 24, seq=1
    )
    assert spec.verify()
    build = gen.generate("petstore", "python", "petstore-sdk", "1.2.3", seq=2)
    assert build.verify()
    assert "petstore-sdk 1.2.3 (python)" in build.bundle_text
    pub = gen.publish(build.build_id, "pypi", seq=3)
    assert pub.verify() and pub.active
    child = gen.version(build.build_id, "minor", seq=4)
    assert child.sdk_version == "1.3.0"
    assert child.prev_build_id == build.build_id
    assert child.verify()
    wd = gen.withdraw(pub.publish_id, seq=5, reason="yank")
    assert wd.verify()
    assert gen.active_publication(build.build_id, "pypi") is None
    # refusal smoke
    try:
        gen.generate("nope", "python", "x", "1.0.0", seq=6)
    except UnknownSpecError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected UnknownSpecError")
    print(
        "sdk-generation OK: register, generate, publish, version, withdraw, pins"
    )


if __name__ == "__main__":  # pragma: no cover
    main()
