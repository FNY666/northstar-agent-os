"""Private inference query-policy ledger (Private ML governance layer, NOT real crypto).

Research context: Private ML (homomorphic inference, TEE serving, DP prediction)
lets clients obtain predictions without exposing raw inputs. This module is the
**governance layer** over such endpoints — it books who may query a private
model, how much privacy budget each query consumes, and whether the declared
response respected the privacy policy. It is deliberately distinct from the
sibling layers on this tree:

* ``secure_inference.py`` — sealed-input execution (simulated encrypted
  inference): owns the *execution* half, "this pinned model produced this
  prediction on this sealed input".
* ``dp_accountant.py`` — float-based (epsilon, delta) privacy accounting: owns
  the *accountant* math, no notion of clients, models, or queries.
* ``model_serving.py`` — KServe-shaped deployment lifecycle: owns deployment
  bookkeeping, no privacy semantics.

This module owns the *query policy* half: endpoint registration, per-client
query quotas, exact-fraction epsilon spend per response, and refusal semantics
when a budget is exhausted. It simulates nothing cryptographically and runs no
model: booked epsilons are host-reported ledger truth, never verified DP
guarantees. A "noise-applied" outcome means the host *declared* noise was
applied; the module cannot verify a real DP mechanism ran.

Deterministic single-host state machine, house style throughout:

* frozen dataclasses, caller int seqs strictly increasing (claim-then-burn:
  failed mutations consume their seq and book ``private-inference.rejected``;
  rewinds raise bare without consuming);
* no wall-clock, RLock-guarded, fail-closed taxonomy, stdlib-only with the
  ``canonical_json`` try/except fallback, ``sha256:`` digest pins, exact
  fraction epsilon arithmetic (``num/den`` text, no floats), ``audit.ndjson/1``
  events with raw content banned from the audit boundary;
* honest scope: quota and budget enforcement are ledger discipline — a host
  that bypasses the module can still over-query; ``respond()`` books declared
  outcomes, never proof of real privacy.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from fractions import Fraction
from math import gcd
from typing import Any, Dict, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

import hashlib

#: Module version.
PRIVATE_INFERENCE_VERSION = "private-inference.v1"

#: Schema pin carried by records and audit events.
PRIVATE_INFERENCE_SCHEMA = "northstar.private-inference.v1"

#: Digest prefix for pins.
_DIGEST_PREFIX = "sha256:"

#: Domain separator so pins cannot collide with other digests.
_HASH_DOMAIN = b"northstar.private-inference.v1\x00"

#: Response outcome vocabulary.
OUTCOMES = ("answered", "noise-applied", "refused")

#: Retire reason vocabulary.
RETIRE_REASONS = ("manual", "policy-violation", "superseded", "compromised")

#: Audit event kinds.
KIND_REGISTERED = "model-registered"
KIND_QUERIED = "query-booked"
KIND_RESPONDED = "response-booked"
KIND_RETIRED = "model-retired"
KIND_REJECTED = "private-inference.rejected"

_KINDS = frozenset({KIND_REGISTERED, KIND_QUERIED, KIND_RESPONDED,
                    KIND_RETIRED, KIND_REJECTED})

#: Raw-text keys banned from crossing the audit boundary.
_BANNED_AUDIT_KEYS = frozenset({
    "query", "content", "input", "prompt", "text", "payload", "value",
    "raw", "data", "secret", "plaintext", "policy",
})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PrivateInferenceError(Exception):
    """Base error for private-inference misuse."""


class BadModelError(PrivateInferenceError):
    """Malformed model id."""


class DuplicateModelError(PrivateInferenceError):
    """Model id already registered."""


class UnknownModelError(PrivateInferenceError):
    """Model id not registered."""


class RetiredModelError(PrivateInferenceError):
    """Model id retired; ids are never recycled."""


class BadClientError(PrivateInferenceError):
    """Malformed client id."""


class BadDigestError(PrivateInferenceError):
    """Malformed sha256 digest pin."""


class BadQuotaError(PrivateInferenceError):
    """Malformed query quota."""


class QuotaExhaustedError(PrivateInferenceError):
    """Client has consumed its query quota for the model."""


class BadOutcomeError(PrivateInferenceError):
    """Outcome outside the pinned vocabulary."""


class BadEpsilonError(PrivateInferenceError):
    """Malformed epsilon spend (non-negative num, positive den required)."""


class UnknownQueryError(PrivateInferenceError):
    """Query id not booked."""


class DuplicateResponseError(PrivateInferenceError):
    """Query already has a booked response."""


class BadReasonError(PrivateInferenceError):
    """Reason outside the pinned vocabulary."""


class SeqOrderError(PrivateInferenceError):
    """Caller seq is not strictly increasing (or is a bool/non-int)."""


class AuditKindError(PrivateInferenceError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _digest_pin(payload: Any) -> str:
    """Pin *payload* as a ``sha256:<hex>`` digest via the canonical form."""
    if _cj is not None and hasattr(_cj, "jcs_dumps"):
        try:
            raw = _cj.jcs_dumps(payload)
            blob = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
        except Exception:
            blob = repr(payload).encode("utf-8")
    else:  # stdlib fallback
        import json as _json

        blob = _json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")
    return _DIGEST_PREFIX + hashlib.sha256(_HASH_DOMAIN + blob).hexdigest()


def _check_id(name: str, value: Any, error_cls: type) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise error_cls(f"{name} must be a str")
    if not value or len(value) > 128:
        raise error_cls(f"{name} must be non-empty and <=128 chars")
    if any(ch.isspace() for ch in value):
        raise error_cls(f"{name} must not contain whitespace")
    return value


def _check_digest(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError("digest must be a str")
    if not value:
        return ""
    if not value.startswith(_DIGEST_PREFIX):
        raise BadDigestError("digest must be a sha256: pin (or empty)")
    hexpart = value[len(_DIGEST_PREFIX):]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError("digest hex part must be 64 lowercase hex chars")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    if seq < 0:
        raise SeqOrderError("seq must be >= 0")
    return seq


def _reduce(num: int, den: int) -> Tuple[int, int]:
    g = gcd(num, den)
    return num // g, den // g


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelRecord:
    model_id: str
    query_quota: int
    policy_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": PRIVATE_INFERENCE_SCHEMA,
            "model_id": self.model_id,
            "query_quota": self.query_quota,
            "policy_digest": self.policy_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class QueryRecord:
    query_id: str
    client_id: str
    model_id: str
    query_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": PRIVATE_INFERENCE_SCHEMA,
            "query_id": self.query_id,
            "client_id": self.client_id,
            "model_id": self.model_id,
            "query_digest": self.query_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ResponseRecord:
    response_id: str
    query_id: str
    outcome: str
    eps_text: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": PRIVATE_INFERENCE_SCHEMA,
            "response_id": self.response_id,
            "query_id": self.query_id,
            "outcome": self.outcome,
            "eps_text": self.eps_text,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RetireRecord:
    model_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": PRIVATE_INFERENCE_SCHEMA,
            "model_id": self.model_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class AuditReport:
    model_id: str
    total_queries: int
    total_responses: int
    outcomes: Tuple[Tuple[str, int], ...]
    per_client: Tuple[Tuple[str, int], ...]
    eps_total_text: str
    quota_remaining: Tuple[Tuple[str, int], ...]
    denied_queries: int
    seq: int
    digest: str

    def verify(self) -> bool:
        body = {
            "model_id": self.model_id,
            "total_queries": self.total_queries,
            "total_responses": self.total_responses,
            "outcomes": [list(pair) for pair in self.outcomes],
            "per_client": [list(pair) for pair in self.per_client],
            "eps_total_text": self.eps_total_text,
            "quota_remaining": [list(pair) for pair in self.quota_remaining],
            "denied_queries": self.denied_queries,
            "seq": self.seq,
        }
        return _digest_pin(body) == self.digest

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": PRIVATE_INFERENCE_SCHEMA,
            "model_id": self.model_id,
            "total_queries": self.total_queries,
            "total_responses": self.total_responses,
            "outcomes": [{"outcome": o, "count": c} for o, c in self.outcomes],
            "per_client": [{"client_id": c, "queries": n}
                           for c, n in self.per_client],
            "eps_total_text": self.eps_total_text,
            "quota_remaining": [{"client_id": c, "remaining": r}
                                for c, r in self.quota_remaining],
            "denied_queries": self.denied_queries,
            "seq": self.seq,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def private_inference_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event dict."""
    _check_seq(seq)
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    bad = [k for k in detail if k in _BANNED_AUDIT_KEYS]
    if bad:
        raise AuditKindError(f"raw keys banned from audit boundary: {bad}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class PrivateInference:
    """Private-inference query-policy ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._models: Dict[str, ModelRecord] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._queries: Dict[str, QueryRecord] = {}
        self._responses: Dict[str, ResponseRecord] = {}
        self._answered_queries: set = set()
        self._client_usage: Dict[Tuple[str, str], int] = {}
        self._denied: Dict[str, int] = {}
        self._query_counter = 0
        self._response_counter = 0
        self._audit_log: list = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: int) -> None:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError("seq must strictly increase")

    def _burn(self, seq: int, note: str) -> None:
        """Consume *seq* and book a rejected row after a failed mutation."""
        self._last_seq = seq
        self._audit_log.append(
            private_inference_audit_event(KIND_REJECTED, seq, note=note))

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(
            private_inference_audit_event(audit_kind, seq, **detail))

    # -- mutations ----------------------------------------------------------

    def register_model(self, model_id: str, seq: int, query_quota: int,
                       policy_digest: str = "") -> ModelRecord:
        """Declare a private inference endpoint with a per-client quota."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id("model_id", model_id, BadModelError)
                if isinstance(query_quota, bool) or not isinstance(query_quota, int):
                    raise BadQuotaError("query_quota must be an int")
                if query_quota < 1:
                    raise BadQuotaError("query_quota must be >= 1")
                _check_digest(policy_digest)
                if model_id in self._retired:
                    raise RetiredModelError(f"model retired: {model_id!r}")
                if model_id in self._models:
                    raise DuplicateModelError(f"model exists: {model_id!r}")
                digest = _digest_pin({"model_id": model_id,
                                      "query_quota": query_quota,
                                      "policy_digest": policy_digest})
                rec = ModelRecord(model_id, query_quota, policy_digest,
                                  seq, digest)
                self._models[model_id] = rec
                self._last_seq = seq
                self._emit(KIND_REGISTERED, seq, model_id=model_id,
                           query_quota=query_quota,
                           policy_digest=policy_digest)
                return rec
            except PrivateInferenceError:
                self._burn(seq, "register_model")
                raise

    def query(self, client_id: str, model_id: str, seq: int,
              query_digest: str = "") -> QueryRecord:
        """Book one inference request against a client's quota."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id("client_id", client_id, BadClientError)
                _check_id("model_id", model_id, BadModelError)
                _check_digest(query_digest)
                if model_id in self._retired:
                    raise RetiredModelError(f"model retired: {model_id!r}")
                if model_id not in self._models:
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                quota = self._models[model_id].query_quota
                used = self._client_usage.get((client_id, model_id), 0)
                if used >= quota:
                    self._denied[model_id] = self._denied.get(model_id, 0) + 1
                    raise QuotaExhaustedError(
                        f"quota exhausted for {client_id!r} on {model_id!r}")
                self._query_counter += 1
                query_id = f"qry-{self._query_counter}"
                digest = _digest_pin({"query_id": query_id,
                                      "client_id": client_id,
                                      "model_id": model_id,
                                      "query_digest": query_digest})
                rec = QueryRecord(query_id, client_id, model_id,
                                  query_digest, seq, digest)
                self._queries[query_id] = rec
                self._client_usage[(client_id, model_id)] = used + 1
                self._last_seq = seq
                self._emit(KIND_QUERIED, seq, query_id=query_id,
                           client_id=client_id, model_id=model_id,
                           query_digest=query_digest)
                return rec
            except PrivateInferenceError:
                self._burn(seq, "query")
                raise

    def respond(self, query_id: str, seq: int, outcome: str,
                eps_num: int = 0, eps_den: int = 1) -> ResponseRecord:
        """Book the host-declared privacy-preserving response."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id("query_id", query_id, UnknownQueryError)
                if isinstance(outcome, bool) or outcome not in OUTCOMES:
                    raise BadOutcomeError(f"outcome must be one of {OUTCOMES}")
                if isinstance(eps_num, bool) or not isinstance(eps_num, int):
                    raise BadEpsilonError("eps_num must be an int")
                if isinstance(eps_den, bool) or not isinstance(eps_den, int):
                    raise BadEpsilonError("eps_den must be an int")
                if eps_num < 0 or eps_den < 1:
                    raise BadEpsilonError("eps_num >= 0, eps_den >= 1 required")
                if query_id not in self._queries:
                    raise UnknownQueryError(f"unknown query: {query_id!r}")
                if query_id in self._answered_queries:
                    raise DuplicateResponseError(
                        f"query already answered: {query_id!r}")
                num, den = _reduce(eps_num, eps_den)
                eps_text = f"{num}/{den}"
                self._response_counter += 1
                response_id = f"rsp-{self._response_counter}"
                digest = _digest_pin({"response_id": response_id,
                                      "query_id": query_id,
                                      "outcome": outcome,
                                      "eps_text": eps_text})
                rec = ResponseRecord(response_id, query_id, outcome,
                                     eps_text, seq, digest)
                self._responses[response_id] = rec
                self._answered_queries.add(query_id)
                self._last_seq = seq
                self._emit(KIND_RESPONDED, seq, response_id=response_id,
                           query_id=query_id, outcome=outcome,
                           eps_text=eps_text)
                return rec
            except PrivateInferenceError:
                self._burn(seq, "respond")
                raise

    def retire(self, model_id: str, seq: int,
               reason: str = "manual") -> RetireRecord:
        """Terminally retire a model endpoint; the id is never recycled."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id("model_id", model_id, BadModelError)
                if isinstance(reason, bool) or reason not in RETIRE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {RETIRE_REASONS}")
                if model_id in self._retired:
                    raise RetiredModelError(f"model retired: {model_id!r}")
                if model_id not in self._models:
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                digest = _digest_pin({"model_id": model_id, "reason": reason})
                rec = RetireRecord(model_id, reason, seq, digest)
                self._retired[model_id] = rec
                self._last_seq = seq
                self._emit(KIND_RETIRED, seq, model_id=model_id, reason=reason)
                return rec
            except PrivateInferenceError:
                self._burn(seq, "retire")
                raise

    # -- pure-read views ----------------------------------------------------

    def audit(self, seq: int, model_id: str) -> AuditReport:
        """Pure read: privacy-accounting report for one model endpoint."""
        with self._lock:
            _check_seq(seq)
            _check_id("model_id", model_id, BadModelError)
            if model_id in self._retired:
                raise RetiredModelError(f"model retired: {model_id!r}")
            if model_id not in self._models:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            quota = self._models[model_id].query_quota
            queries = [q for q in self._queries.values()
                       if q.model_id == model_id]
            responses = [r for r in self._responses.values()
                         if self._queries[r.query_id].model_id == model_id]
            outcome_counts: Dict[str, int] = {o: 0 for o in OUTCOMES}
            for r in responses:
                outcome_counts[r.outcome] += 1
            eps_total = Fraction(0, 1)
            for r in responses:
                num, den = (int(x) for x in r.eps_text.split("/"))
                eps_total += Fraction(num, den)
            per_client: Dict[str, int] = {}
            for q in queries:
                per_client[q.client_id] = per_client.get(q.client_id, 0) + 1
            clients = sorted({q.client_id for q in queries})
            quota_remaining = tuple(
                (c, quota - per_client.get(c, 0)) for c in clients)
            body = {
                "model_id": model_id,
                "total_queries": len(queries),
                "total_responses": len(responses),
                "outcomes": [[o, outcome_counts[o]] for o in OUTCOMES],
                "per_client": [[c, per_client[c]]
                               for c in sorted(per_client)],
                "eps_total_text": f"{eps_total.numerator}/{eps_total.denominator}",
                "quota_remaining": [list(pair) for pair in quota_remaining],
                "denied_queries": self._denied.get(model_id, 0),
                "seq": seq,
            }
            digest = _digest_pin(body)
            return AuditReport(
                model_id=model_id,
                total_queries=len(queries),
                total_responses=len(responses),
                outcomes=tuple((o, outcome_counts[o]) for o in OUTCOMES),
                per_client=tuple(sorted(per_client.items())),
                eps_total_text=f"{eps_total.numerator}/{eps_total.denominator}",
                quota_remaining=quota_remaining,
                denied_queries=self._denied.get(model_id, 0),
                seq=seq,
                digest=digest,
            )

    def model_record(self, model_id: str) -> ModelRecord:
        with self._lock:
            _check_id("model_id", model_id, BadModelError)
            if model_id in self._retired:
                raise RetiredModelError(f"model retired: {model_id!r}")
            if model_id not in self._models:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            return self._models[model_id]

    def query_record(self, query_id: str) -> QueryRecord:
        with self._lock:
            _check_id("query_id", query_id, UnknownQueryError)
            if query_id not in self._queries:
                raise UnknownQueryError(f"unknown query: {query_id!r}")
            return self._queries[query_id]

    def response_record(self, response_id: str) -> ResponseRecord:
        with self._lock:
            _check_id("response_id", response_id, UnknownQueryError)
            if response_id not in self._responses:
                raise UnknownQueryError(
                    f"unknown response: {response_id!r}")
            return self._responses[response_id]

    def model_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._models))

    def retired_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._retired))

    def query_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._queries))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(row) for row in self._audit_log)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "models": len(self._models),
                "retired": len(self._retired),
                "queries": len(self._queries),
                "responses": len(self._responses),
                "audit_rows": len(self._audit_log),
            }


def main() -> None:
    """Self-check entry point."""
    pi = PrivateInference()
    policy = _digest_pin({"epsilon": "1/1", "note": "host-declared"})
    pi.register_model("private-llm", 1, 2, policy)
    q1 = pi.query("alice", "private-llm", 2)
    r1 = pi.respond(q1.query_id, 3, "noise-applied", eps_num=1, eps_den=2)
    q2 = pi.query("alice", "private-llm", 4)
    pi.respond(q2.query_id, 5, "answered", eps_num=1, eps_den=2)
    rep = pi.audit(6, "private-llm")
    assert rep.verify()
    assert rep.total_queries == 2
    assert rep.eps_total_text == "1/1"
    assert rep.denied_queries == 0
    try:
        pi.query("alice", "private-llm", 7)
    except QuotaExhaustedError:
        pass
    rep2 = pi.audit(8, "private-llm")
    assert rep2.denied_queries == 1
    assert r1.eps_text == "1/2"
    print("private-inference OK: register, query, respond, audit, quota, pins")


if __name__ == "__main__":
    main()
