"""Consumer-driven contract tester (Pact style, simulated).

Research motivation: in a multi-agent runtime, agents are both
consumers and providers of tool interfaces. When a provider ships a
breaking change to a tool's request/response shape, every consumer
agent breaks at runtime. Consumer-driven contract testing fixes the
direction: consumers record the interactions they depend on, the
provider verifies those pacts before deploying, and a broker answers
"can I deploy this provider version without breaking any consumer?".

This module is the *bookkeeping* half of that shape (no HTTP, no
network -- the host supplies provider stubs; this module pins and
compares them):

- ``ContractTester`` -- owns the pact ledger. ``pact()`` records a
  consumer's expected interactions against a provider and returns a
  frozen, digest-pinned ``PactRecord``; ``verify()`` replays a pact's
  interactions against the provider's registered stubs and returns a
  frozen ``VerificationReport`` (per-interaction pass/fail, never
  raising on a mismatch); ``broker()`` answers the can-i-deploy
  question with a frozen ``BrokerReport`` matrix. ``publish_provider()``
  pins provider versions; ``stub()`` registers provider behavior.
- ``contract_tester_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``pact-created`` / ``verified`` / ``stub-registered`` /
  ``provider-published`` / ``rejected``); ids and digest pins only --
  request/response bodies never cross the audit boundary.

Fail-closed edges (fail loudly, never guess):

- ``pact()`` interactions must be a non-empty list; each interaction
  needs ``description`` (non-empty str), ``method`` (pinned HTTP verb),
  ``path`` (absolute path), ``status`` (int 100-599); bodies must be
  JSON-canonicalizable (NaN/inf and |n| >= 2**53 refused -- batch-5
  JCS discipline); violations raise ``BadInteractionError``.
- ``(consumer, provider, version)`` triples are unique; re-recording
  the same triple raises ``DuplicatePactError``.
- ``verify()`` of an unknown pact raises ``UnknownPactError``.
  Verification *mismatches* are verdict data, not exceptions:
  the report records ``passed``/``failed`` per interaction with
  reasons ``mismatch`` (status/body/headers differ) or ``no-stub``
  (provider never registered behavior for this method+path).
- Response matching is exact: method and path must match exactly;
  recorded status must equal the stub status; recorded expected
  headers must be a subset of the stub headers (extra stub headers
  are fine); bodies compare byte-equal under JCS canonicalization.
- Mutating calls consume strictly increasing caller-supplied int
  seqs (no wall-clock); rewinds raise ``SeqOrderError``. A failed
  mutation consumes its seq (fail-closed ledger position).

Honest scope:

- This module is simulated bookkeeping, not a contract broker over
  the network: ``stub()`` pins host-reported provider behavior, and
  ``verify()`` compares the pact against those pinned stubs. It
  cannot observe a real provider's responses -- a lying host gets a
  lying verification (GIGO boundary).
- A ``passed`` verification means "the pinned stubs satisfy the
  recorded expectations", never "the deployed provider is safe".
  Pair with an attested provider harness for production gating.
- In-memory only: pair with the durable audit writer if pacts must
  survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return _hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
CONTRACT_TESTER_VERSION = "contract-tester.v1"

#: Schema pin carried by records and audit events.
CONTRACT_TESTER_SCHEMA = "northstar.contract-tester.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned HTTP method vocabulary for interactions.
METHODS: Tuple[str, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")

#: Audit event kinds.
KIND_PACT_CREATED = "pact-created"
KIND_VERIFIED = "verified"
KIND_STUB_REGISTERED = "stub-registered"
KIND_PROVIDER_PUBLISHED = "provider-published"
KIND_REJECTED = "rejected"
_KINDS = (KIND_PACT_CREATED, KIND_VERIFIED, KIND_STUB_REGISTERED,
          KIND_PROVIDER_PUBLISHED, KIND_REJECTED)

#: Broker matrix statuses.
VERIFIED = "verified"
FAILED = "failed"
NEVER_VERIFIED = "never-verified"

#: Verification failure reasons.
REASON_MISMATCH = "mismatch"
REASON_NO_STUB = "no-stub"

#: Fields that must never cross the audit boundary (user content).
_BANNED_AUDIT_FIELDS = ("request", "response", "body", "headers", "interactions")


class ContractTesterError(Exception):
    """Base error for the contract tester."""


class BadInteractionError(ContractTesterError):
    """An interaction violates the pinned shape (method/path/status/body)."""


class DuplicatePactError(ContractTesterError):
    """The (consumer, provider, version) triple is already recorded."""


class UnknownPactError(ContractTesterError):
    """verify() was given a pact id the ledger never recorded."""


class DuplicateStubError(ContractTesterError):
    """A stub for (provider, method, path) is already registered."""


class UnknownProviderError(ContractTesterError):
    """A provider was never published or never stubbed."""


class DuplicateProviderError(ContractTesterError):
    """The (provider, version) pair was already published."""


class SeqOrderError(ContractTesterError):
    """A caller seq is not a strictly increasing int (no wall-clock)."""


class BadAuditKindError(ContractTesterError):
    """The audit event kind is not one of the pinned kinds."""


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"{what} must be an int >= 0 (not bool)")
    return seq


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractTesterError(f"{what} must be a non-empty str")
    return value


def _pin(*parts: Any) -> str:
    return "sha256:" + jcs_sha256_hex(list(parts))


def _sha256_hex_bytes(blob: bytes) -> str:
    """Hex-digest already-canonical bytes (jcs_sha256_hex needs an object)."""
    return hashlib.sha256(blob).hexdigest()


def _canonical_body(body: Any, what: str) -> bytes:
    """JCS-canonicalize a body, refusing non-finite/unsafe numerics."""
    try:
        blob = jcs_canonical_json(body)
    except (TypeError, ValueError) as exc:
        raise BadInteractionError(f"{what} is not JSON-canonicalizable: {exc}") from exc
    _refuse_unsafe_numbers(body, what)
    return blob


def _refuse_unsafe_numbers(obj: Any, what: str) -> None:
    if isinstance(obj, bool):
        return
    if isinstance(obj, float):
        if obj != obj or obj in (float("inf"), float("-inf")):
            raise BadInteractionError(f"{what} must not contain NaN/inf")
    elif isinstance(obj, int):
        if abs(obj) >= 2 ** 53:
            raise BadInteractionError(f"{what} must not contain |n| >= 2**53")
    elif isinstance(obj, Mapping):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise BadInteractionError(f"{what} keys must be strings")
            _refuse_unsafe_numbers(v, what)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _refuse_unsafe_numbers(v, what)


def _check_headers(headers: Any, what: str) -> Dict[str, str]:
    if not isinstance(headers, Mapping):
        raise BadInteractionError(f"{what} headers must be a mapping")
    out: Dict[str, str] = {}
    for k, v in headers.items():
        if not isinstance(k, str) or not k:
            raise BadInteractionError(f"{what} header names must be non-empty str")
        if not isinstance(v, str):
            raise BadInteractionError(f"{what} header values must be str")
        out[k.lower()] = v
    return out


@dataclass(frozen=True)
class Interaction:
    """A single pinned consumer interaction: description, request, response."""

    description: str
    method: str
    path: str
    expected_status: int
    # Request headers are recorded only (the stub key is method+path);
    # response headers are the verified subset.
    request_headers: Tuple[Tuple[str, str], ...]
    request_body_digest: str
    response_headers: Tuple[Tuple[str, str], ...]
    response_body_digest: str
    interaction_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "method": self.method,
            "path": self.path,
            "expected_status": self.expected_status,
            "request_headers": [list(h) for h in self.request_headers],
            "request_body_digest": self.request_body_digest,
            "response_headers": [list(h) for h in self.response_headers],
            "response_body_digest": self.response_body_digest,
            "interaction_digest": self.interaction_digest,
        }


@dataclass(frozen=True)
class PactRecord:
    """A recorded consumer-driven contract, digest-pinned."""

    pact_id: str
    consumer: str
    provider: str
    version: str
    interactions: Tuple[Interaction, ...]
    interaction_count: int
    pact_digest: str
    version_pin: str = CONTRACT_TESTER_VERSION
    schema: str = CONTRACT_TESTER_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "pact_id": self.pact_id,
            "consumer": self.consumer,
            "provider": self.provider,
            "version": self.version,
            "interactions": [i.as_dict() for i in self.interactions],
            "interaction_count": self.interaction_count,
            "pact_digest": self.pact_digest,
            "version_pin": self.version_pin,
            "schema": self.schema,
        }

    def verify(self, interactions: List[Dict[str, Any]]) -> bool:
        """Re-derive the pact digest from raw interaction dicts."""
        recomputed = _build_pact_digest(self.consumer, self.provider,
                                        self.version, interactions)
        return recomputed == self.pact_digest


def _build_pact_digest(consumer: str, provider: str, version: str,
                       raw_interactions: List[Dict[str, Any]]) -> str:
    # Digest over the raw, caller-supplied interactions (GIGO pin).
    return _pin("pact", CONTRACT_TESTER_VERSION, consumer, provider,
                version, jcs_sha256_hex(raw_interactions))


@dataclass(frozen=True)
class StubRecord:
    """Pinned provider behavior for one (method, path) pair."""

    stub_id: str
    provider: str
    method: str
    path: str
    status: int
    headers: Tuple[Tuple[str, str], ...]
    body_digest: str
    stub_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "stub_id": self.stub_id,
            "provider": self.provider,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "headers": [list(h) for h in self.headers],
            "body_digest": self.body_digest,
            "stub_digest": self.stub_digest,
        }


@dataclass(frozen=True)
class InteractionResult:
    """The verification verdict for one recorded interaction."""

    description: str
    method: str
    path: str
    passed: bool
    reason: str  # "match" | REASON_MISMATCH | REASON_NO_STUB
    mismatch_detail: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "method": self.method,
            "path": self.path,
            "passed": self.passed,
            "reason": self.reason,
            "mismatch_detail": self.mismatch_detail,
        }


@dataclass(frozen=True)
class VerificationReport:
    """The frozen verdict of replaying a pact against pinned stubs."""

    report_id: str
    pact_id: str
    consumer: str
    provider: str
    provider_version: Optional[str]
    results: Tuple[InteractionResult, ...]
    passed: int
    failed: int
    all_passed: bool
    report_digest: str
    version_pin: str = CONTRACT_TESTER_VERSION
    schema: str = CONTRACT_TESTER_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "pact_id": self.pact_id,
            "consumer": self.consumer,
            "provider": self.provider,
            "provider_version": self.provider_version,
            "results": [r.as_dict() for r in self.results],
            "passed": self.passed,
            "failed": self.failed,
            "all_passed": self.all_passed,
            "report_digest": self.report_digest,
            "version_pin": self.version_pin,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class MatrixRow:
    """One can-i-deploy cell: consumer pact vs published provider version."""

    consumer: str
    consumer_version: str
    provider: str
    provider_version: str
    status: str  # VERIFIED | FAILED | NEVER_VERIFIED

    def as_dict(self) -> Dict[str, Any]:
        return {
            "consumer": self.consumer,
            "consumer_version": self.consumer_version,
            "provider": self.provider,
            "provider_version": self.provider_version,
            "status": self.status,
        }


@dataclass(frozen=True)
class BrokerReport:
    """The frozen compatibility matrix over all pacts and provider versions."""

    rows: Tuple[MatrixRow, ...]
    row_count: int
    all_verified: bool
    report_digest: str
    version_pin: str = CONTRACT_TESTER_VERSION
    schema: str = CONTRACT_TESTER_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rows": [r.as_dict() for r in self.rows],
            "row_count": self.row_count,
            "all_verified": self.all_verified,
            "report_digest": self.report_digest,
            "version_pin": self.version_pin,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ProviderVersion:
    """A published provider version, digest-pinned."""

    provider: str
    version: str
    version_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "version": self.version,
            "version_digest": self.version_digest,
        }


class ContractTester:
    """Consumer-driven contract ledger: pact / stub / verify / broker."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._pact_seq = 0
        self._stub_seq = 0
        self._report_seq = 0
        self._pacts: Dict[str, PactRecord] = {}
        self._pact_triples: Dict[Tuple[str, str, str], str] = {}
        self._stubs: Dict[Tuple[str, str, str], StubRecord] = {}
        self._provider_versions: Dict[str, List[ProviderVersion]] = {}
        # pact_id -> {provider_version -> all_passed} from verifications.
        self._verification_history: Dict[str, Dict[str, bool]] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: Any, what: str = "seq") -> int:
        _check_seq(seq, what)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"{what} must be strictly increasing "
                    f"(last={self._last_seq}, got={seq})")
            self._last_seq = seq
        return seq

    def _audit_event(self, kind: str, detail: Dict[str, Any],
                     seq: int) -> Dict[str, Any]:
        if kind not in _KINDS:
            raise BadAuditKindError(f"unknown audit kind: {kind!r}")
        for banned in _BANNED_AUDIT_FIELDS:
            if banned in detail:
                raise ContractTesterError(
                    f"audit detail must not carry {banned!r}")
        event = {
            "schema": AUDIT_SCHEMA,
            "kind": kind,
            "seq": seq,
            "detail": detail,
        }
        with self._lock:
            self._audit.append(event)
        return event

    def _build_interaction(self, raw: Any) -> Interaction:
        if not isinstance(raw, Mapping):
            raise BadInteractionError("interaction must be a mapping")
        description = raw.get("description")
        method = raw.get("method")
        path = raw.get("path")
        status = raw.get("status")
        _check_str(description, "interaction description")
        if method not in METHODS:
            raise BadInteractionError(
                f"interaction method must be one of {METHODS}")
        _check_str(path, "interaction path")
        if not path.startswith("/"):
            raise BadInteractionError("interaction path must be absolute")
        if isinstance(status, bool) or not isinstance(status, int) \
                or not (100 <= status <= 599):
            raise BadInteractionError(
                "interaction status must be an int in [100, 599]")
        request = raw.get("request", {})
        response = raw.get("response", {})
        if not isinstance(request, Mapping) or not isinstance(response, Mapping):
            raise BadInteractionError(
                "interaction request/response must be mappings")
        req_headers = _check_headers(request.get("headers", {}), "request")
        resp_headers = _check_headers(response.get("headers", {}), "response")
        req_body_blob = _canonical_body(request.get("body", {}), "request body")
        resp_body_blob = _canonical_body(response.get("body", {}), "response body")
        req_headers_t = tuple(sorted(req_headers.items()))
        resp_headers_t = tuple(sorted(resp_headers.items()))
        interaction_digest = _pin("interaction", description, method, path,
                                  status, req_headers_t,
                                  _sha256_hex_bytes(req_body_blob),
                                  resp_headers_t,
                                  _sha256_hex_bytes(resp_body_blob))
        return Interaction(
            description=description,
            method=method,
            path=path,
            expected_status=status,
            request_headers=req_headers_t,
            request_body_digest="sha256:" + _sha256_hex_bytes(req_body_blob),
            response_headers=resp_headers_t,
            response_body_digest="sha256:" + _sha256_hex_bytes(resp_body_blob),
            interaction_digest=interaction_digest,
        )

    # -- pact -----------------------------------------------------------

    def pact(self, consumer: str, provider: str, seq: int,
             interactions: List[Dict[str, Any]],
             version: str = "1.0.0") -> PactRecord:
        """Record a consumer's contract against a provider.

        ``interactions`` are mappings with ``description``, ``method``,
        ``path``, ``status`` and optional ``request``/``response``
        mappings (each with ``headers`` and ``body``).
        """
        self._claim_seq(seq, "seq")
        _check_str(consumer, "consumer")
        _check_str(provider, "provider")
        _check_str(version, "version")
        if not isinstance(interactions, list) or not interactions:
            raise BadInteractionError(
                "interactions must be a non-empty list")
        built = [self._build_interaction(r) for r in interactions]
        triple = (consumer, provider, version)
        with self._lock:
            if triple in self._pact_triples:
                raise DuplicatePactError(
                    f"pact already recorded for {triple}")
            self._pact_seq += 1
            pact_id = f"pact-{self._pact_seq}"
        # Digest over the raw, caller-supplied interactions (GIGO pin):
        digest = _build_pact_digest(consumer, provider, version, interactions)
        record = PactRecord(
            pact_id=pact_id,
            consumer=consumer,
            provider=provider,
            version=version,
            interactions=tuple(built),
            interaction_count=len(built),
            pact_digest=digest,
        )
        with self._lock:
            self._pacts[pact_id] = record
            self._pact_triples[triple] = pact_id
        self._audit_event(KIND_PACT_CREATED, {
            "pact_id": pact_id,
            "consumer": consumer,
            "provider": provider,
            "version": version,
            "interaction_count": len(built),
            "pact_digest": digest,
        }, seq)
        return record

    def pact_record(self, pact_id: str) -> PactRecord:
        with self._lock:
            if pact_id not in self._pacts:
                raise UnknownPactError(f"unknown pact: {pact_id!r}")
            return self._pacts[pact_id]

    def pact_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._pacts))

    # -- stubs ----------------------------------------------------------

    def stub(self, provider: str, method: str, path: str, seq: int,
             status: int = 200,
             headers: Optional[Mapping[str, str]] = None,
             body: Any = None) -> StubRecord:
        """Register host-reported provider behavior for (method, path)."""
        self._claim_seq(seq, "seq")
        _check_str(provider, "provider")
        _check_str(path, "path")
        if method not in METHODS:
            raise BadInteractionError(
                f"stub method must be one of {METHODS}")
        if not path.startswith("/"):
            raise BadInteractionError("stub path must be absolute")
        if isinstance(status, bool) or not isinstance(status, int) \
                or not (100 <= status <= 599):
            raise BadInteractionError("stub status must be an int in [100, 599]")
        hdrs = _check_headers(headers or {}, "stub")
        blob = _canonical_body(body if body is not None else {}, "stub body")
        key = (provider, method, path)
        with self._lock:
            if key in self._stubs:
                raise DuplicateStubError(f"stub already registered for {key}")
            self._stub_seq += 1
            stub_id = f"stub-{self._stub_seq}"
            record = StubRecord(
                stub_id=stub_id,
                provider=provider,
                method=method,
                path=path,
                status=status,
                headers=tuple(sorted(hdrs.items())),
                body_digest="sha256:" + _sha256_hex_bytes(blob),
                stub_digest=_pin("stub", provider, method, path, status,
                                 tuple(sorted(hdrs.items())),
                                 _sha256_hex_bytes(blob)),
            )
            self._stubs[key] = record
        self._audit_event(KIND_STUB_REGISTERED, {
            "stub_id": stub_id,
            "provider": provider,
            "method": method,
            "path": path,
            "status": status,
            "stub_digest": record.stub_digest,
        }, seq)
        return record

    # -- verify ---------------------------------------------------------

    def verify(self, pact_id: str, seq: int) -> VerificationReport:
        """Replay a pact's interactions against the pinned stubs.

        Mismatches are verdict data (never raised): each
        ``InteractionResult`` carries ``passed`` plus a reason of
        ``match`` / ``mismatch`` / ``no-stub``.
        """
        self._claim_seq(seq, "seq")
        with self._lock:
            if pact_id not in self._pacts:
                raise UnknownPactError(f"unknown pact: {pact_id!r}")
            pact = self._pacts[pact_id]
            provider_version = self._latest_provider_version(pact.provider)
            results: List[InteractionResult] = []
            for ix in pact.interactions:
                results.append(self._verify_one(pact.provider, ix))
            self._report_seq += 1
            report_id = f"verify-{self._report_seq}"
            passed = sum(1 for r in results if r.passed)
            failed = len(results) - passed
            report = VerificationReport(
                report_id=report_id,
                pact_id=pact_id,
                consumer=pact.consumer,
                provider=pact.provider,
                provider_version=provider_version,
                results=tuple(results),
                passed=passed,
                failed=failed,
                all_passed=failed == 0,
                report_digest=_pin("verify", CONTRACT_TESTER_VERSION,
                                   pact_id, provider_version,
                                   [r.as_dict() for r in results]),
            )
            history = self._verification_history.setdefault(pact_id, {})
            history[str(provider_version)] = report.all_passed
        self._audit_event(KIND_VERIFIED, {
            "report_id": report_id,
            "pact_id": pact_id,
            "provider_version": provider_version,
            "passed": passed,
            "failed": failed,
            "all_passed": report.all_passed,
            "report_digest": report.report_digest,
        }, seq)
        return report

    def _verify_one(self, provider: str,
                    ix: Interaction) -> InteractionResult:
        stub = self._stubs.get((provider, ix.method, ix.path))
        if stub is None:
            return InteractionResult(
                description=ix.description,
                method=ix.method,
                path=ix.path,
                passed=False,
                reason=REASON_NO_STUB,
                mismatch_detail="provider has no stub for this method+path",
            )
        if stub.status != ix.expected_status:
            return InteractionResult(
                description=ix.description,
                method=ix.method,
                path=ix.path,
                passed=False,
                reason=REASON_MISMATCH,
                mismatch_detail=(
                    f"status: expected {ix.expected_status}, "
                    f"stub {stub.status}"),
            )
        stub_headers = dict(stub.headers)
        missing = [k for k, v in ix.response_headers
                   if stub_headers.get(k) != v]
        if missing:
            return InteractionResult(
                description=ix.description,
                method=ix.method,
                path=ix.path,
                passed=False,
                reason=REASON_MISMATCH,
                mismatch_detail="missing/differing headers: "
                                + ", ".join(sorted(missing)),
            )
        if stub.body_digest != ix.response_body_digest:
            return InteractionResult(
                description=ix.description,
                method=ix.method,
                path=ix.path,
                passed=False,
                reason=REASON_MISMATCH,
                mismatch_detail=(
                    f"body: expected {ix.response_body_digest}, "
                    f"stub {stub.body_digest}"),
            )
        return InteractionResult(
            description=ix.description,
            method=ix.method,
            path=ix.path,
            passed=True,
            reason="match",
            mismatch_detail="",
        )

    # -- provider versions ----------------------------------------------

    def publish_provider(self, provider: str, version: str,
                         seq: int) -> ProviderVersion:
        """Pin a provider version for the broker matrix."""
        self._claim_seq(seq, "seq")
        _check_str(provider, "provider")
        _check_str(version, "version")
        with self._lock:
            existing = [pv.version for pv in
                        self._provider_versions.get(provider, [])]
            if version in existing:
                raise DuplicateProviderError(
                    f"provider {provider!r} version {version!r} "
                    "already published")
            record = ProviderVersion(
                provider=provider,
                version=version,
                version_digest=_pin("provider-version", provider, version),
            )
            self._provider_versions.setdefault(provider, []).append(record)
        self._audit_event(KIND_PROVIDER_PUBLISHED, {
            "provider": provider,
            "version": version,
            "version_digest": record.version_digest,
        }, seq)
        return record

    def _latest_provider_version(self, provider: str) -> Optional[str]:
        versions = self._provider_versions.get(provider, [])
        return versions[-1].version if versions else None

    def provider_versions(self, provider: str) -> Tuple[ProviderVersion, ...]:
        with self._lock:
            return tuple(self._provider_versions.get(provider, []))

    # -- broker ---------------------------------------------------------

    def broker(self, seq: int) -> BrokerReport:
        """Answer can-i-deploy: every pact vs every published provider version.

        A cell is ``verified`` when the pact's latest verification ran
        against that provider version and passed, ``failed`` when it
        ran and did not pass, ``never-verified`` otherwise.
        """
        self._claim_seq(seq, "seq")
        rows: List[MatrixRow] = []
        with self._lock:
            for pact_id, pact in self._pacts.items():
                versions = self._provider_versions.get(pact.provider, [])
                if not versions:
                    rows.append(MatrixRow(
                        consumer=pact.consumer,
                        consumer_version=pact.version,
                        provider=pact.provider,
                        provider_version="-",
                        status=NEVER_VERIFIED,
                    ))
                    continue
                history = self._verification_history.get(pact_id, {})
                for pv in versions:
                    key = str(pv.version)
                    if key not in history:
                        status = NEVER_VERIFIED
                    else:
                        status = VERIFIED if history[key] else FAILED
                    rows.append(MatrixRow(
                        consumer=pact.consumer,
                        consumer_version=pact.version,
                        provider=pact.provider,
                        provider_version=pv.version,
                        status=status,
                    ))
            rows_sorted = tuple(sorted(
                rows, key=lambda r: (r.provider, r.provider_version,
                                     r.consumer, r.consumer_version)))
            all_verified = bool(rows_sorted) and all(
                r.status == VERIFIED for r in rows_sorted)
            report = BrokerReport(
                rows=rows_sorted,
                row_count=len(rows_sorted),
                all_verified=all_verified,
                report_digest=_pin("broker", CONTRACT_TESTER_VERSION,
                                   [r.as_dict() for r in rows_sorted]),
            )
        return report

    # -- views ----------------------------------------------------------

    def verification_history(self, pact_id: str) -> Dict[str, bool]:
        with self._lock:
            if pact_id not in self._pacts:
                raise UnknownPactError(f"unknown pact: {pact_id!r}")
            return dict(self._verification_history.get(pact_id, {}))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def contract_tester_audit_event(kind: str, seq: Any,
                                detail: Optional[Mapping[str, Any]] = None
                                ) -> Dict[str, Any]:
    """Build a standalone ``audit.ndjson/1`` record for this module."""
    _check_seq(seq, "seq")
    if kind not in _KINDS:
        raise BadAuditKindError(f"unknown audit kind: {kind!r}")
    detail = dict(detail or {})
    for banned in _BANNED_AUDIT_FIELDS:
        if banned in detail:
            raise ContractTesterError(
                f"audit detail must not carry {banned!r}")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }


def main() -> None:
    t = ContractTester()
    s = 0

    def nxt() -> int:
        nonlocal s
        s += 1
        return s

    t.publish_provider("billing", "2.0.0", nxt())
    t.stub("billing", "GET", "/invoices/42", nxt(), status=200,
           headers={"Content-Type": "application/json"},
           body={"id": 42, "total_cents": 1999})
    pact = t.pact("invoice-ui", "billing", nxt(), [
        {"description": "fetch invoice",
         "method": "GET",
         "path": "/invoices/42",
         "status": 200,
         "request": {"headers": {}},
         "response": {"headers": {"Content-Type": "application/json"},
                      "body": {"id": 42, "total_cents": 1999}}},
    ], version="1.0.0")
    report = t.verify(pact.pact_id, nxt())
    assert report.all_passed and report.passed == 1 and report.failed == 0
    matrix = t.broker(nxt())
    assert matrix.all_verified and matrix.row_count == 1
    assert matrix.rows[0].status == VERIFIED

    # mismatch is data, not an exception
    t2 = ContractTester()
    t2.stub("billing", "GET", "/invoices/42", 1, status=200,
            body={"id": 42, "total_cents": 2000})
    p2 = t2.pact("invoice-ui", "billing", 2, [
        {"description": "fetch invoice", "method": "GET",
         "path": "/invoices/42", "status": 200,
         "response": {"body": {"id": 42, "total_cents": 1999}}}])
    r2 = t2.verify(p2.pact_id, 3)
    assert not r2.all_passed and r2.results[0].reason == REASON_MISMATCH

    # unknown pact raises
    try:
        t2.verify("pact-999", 4)
    except UnknownPactError:
        pass
    else:
        raise AssertionError("expected UnknownPactError")

    print("contract-tester OK: pact, stub, verify, broker, mismatch-as-data")


if __name__ == "__main__":
    main()
