"""Provenance attestor: SLSA-shaped build provenance bookkeeping.

Research note: *provenance* answers "who built this artifact, from what
sources, on what platform?" — the core of supply-chain integrity. The SLSA
framework (Supply-chain Levels for Software Artifacts, slsa.dev) standardizes
the answer into three load-bearing ideas:

1. *Attestation statements* — an in-toto attestation (in-toto.io, Statement
   v1) binds a *subject* (artifact name + digest) to a *predicateType*. SLSA
   provenance v1 (``https://slsa.dev/provenance/v1``) is the predicate for
   builds: it carries a ``buildDefinition`` (buildType, externalParameters,
   resolvedDependencies) and ``runDetails`` (builder ``id`` — a URI naming
   the trusted build platform — and an invocationId).
2. *Envelope signing* — the statement is wrapped in a DSSE envelope
   (``payloadType: application/vnd.in-toto+json``, base64 ``payload``,
   ``signatures``) so a verifier can authenticate *who made the claim*,
   not just parse the claim. SLSA levels L1–L3 then describe how much of
   the build platform the consumer must trust (L1: provenance exists; L2:
   hosted build platform; L3: hardened platform).
3. *Policy-gated verification* — verification is not "signature checks
   out"; it is "signature checks out AND the claim satisfies my policy":
   builder allowlist, minimum SLSA level, expected source URI, trusted
   signing keys. A valid signature from an untrusted builder must not
   authorize anything.

This module implements that shape as a deterministic, single-host ledger:

* **Key registry** — :meth:`ProvenanceAttestor.register_key` pins a named
  signing key (HMAC-SHA256 stands in for Ed25519/DSSE signing — the same
  honest-scope caveat as ``jwt_handler``: this is decision bookkeeping,
  not a cryptographic boundary). Secrets never cross the audit boundary
  and are never embedded in any record or digest pin.
* **Attestation** — :meth:`ProvenanceAttestor.attest` builds the in-toto
  v1 statement, seals it in a DSSE-shaped envelope, signs it, and returns
  a frozen :class:`Attestation` with ``sha256:`` statement and envelope
  digest pins. Artifact and material digests must be ``sha256:``-pinned
  hex (fail-closed); the builder id must be a URI; SLSA level is pinned
  to 0–3.
* **Verification** — :meth:`ProvenanceAttestor.verify` re-derives the
  statement pin, checks the signature with constant-time comparison, and
  (optionally) evaluates a named :class:`PolicyRecord`. Failures are
  *verdict data* (``valid=False`` with reason codes), never exceptions —
  except a structurally malformed envelope, which is a programming error
  and raises.
* **Policy** — :meth:`ProvenanceAttestor.policy` pins the verifier's
  trust: trusted builder URIs, minimum SLSA level, expected source URI,
  trusted key ids, optional resolved-dependency requirement. Trusted keys
  must already be registered (fail-closed: trusting a key that does not
  exist hides misconfiguration).

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing on mutating calls, no wall-clock, no RNG), RLock-guarded,
fail-closed error taxonomy (a subclass of :class:`ProvenanceError`),
stdlib-only (``base64``/``hashlib``/``hmac``/``json``/``re``/
``threading``/``dataclasses``/``typing``), type-tagged canonical digest
encoding (bool ≠ int; NaN/inf and integral floats with magnitude > 2⁵³
refused at digest time — the batch-5 JCS float-loss caveat), audit events
shaped for ``audit.ndjson/1``, ``main()`` self-check.

Honest scope: this is a *claims ledger*, not a signature service. It
cannot observe the build, prove that the builder named in the claim is
the builder that ran, or verify that an artifact digest corresponds to a
real file. ``attest()`` pins what the host *reported*; a host that lies
gets a consistent ledger of lies (GIGO, same boundary as every other
bookkeeping module). ``verify()`` proves "this envelope is internally
consistent, signed by a registered key, and policy-conformant" — never
"the software is safe to run". For real provenance pair with
``transparency_log`` and ``remote_attestation``.

Version pin: provenance-attestor.v1
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

#: Module version pin.
PROVENANCE_ATTESTOR_VERSION = "provenance-attestor.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.provenance-attestor.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: in-toto statement type (v1).
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

#: SLSA provenance predicate type (v1).
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"

#: DSSE payload type for in-toto statements.
PAYLOAD_TYPE = "application/vnd.in-toto+json"

#: Pinned SLSA build levels (SLSA v1.0 build track: L1 provenance exists,
#: L2 hosted build platform, L3 hardened platform). Level 0 = "no claim".
SLSA_LEVELS = (0, 1, 2, 3)

#: Digest algorithms accepted for artifact/material digests.
_DIGEST_ALGOS = ("sha256",)

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_BUILDER_URI_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://\S+$")


# ---------------------------------------------------------------------------
# Canonical encoding + digest pins
# ---------------------------------------------------------------------------

def _canonical(value: Any) -> str:
    """Type-tagged canonical encoding (bool ≠ int; NaN/inf and >2⁵³ refused)."""
    if isinstance(value, bool):
        return "bool:" + ("true" if value else "false")
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise ProvenanceError("integer magnitude exceeds 2^53 (digest safety)")
        return "int:" + str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ProvenanceError("NaN/inf cannot be digested")
        if value.is_integer() and abs(value) > 2**53:
            raise ProvenanceError("integral float magnitude exceeds 2^53")
        return "float:" + repr(value)
    if isinstance(value, str):
        return "str:" + json.dumps(value, ensure_ascii=False)
    if value is None:
        return "null"
    if isinstance(value, (list, tuple)):
        return "list:[" + ",".join(_canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: str(kv[0]))
        return "dict:{" + ",".join(
            _canonical(k) + "=" + _canonical(v) for k, v in items) + "}"
    raise ProvenanceError("non-canonicalizable value: %r" % (type(value).__name__,))


def _digest_pin(*parts: Any) -> str:
    body = "\x1f".join(_canonical(p) for p in parts)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class ProvenanceError(Exception):
    """Base error for the provenance attestor."""


class UnknownKeyError(ProvenanceError):
    """A signing key that was never registered."""


class DuplicateKeyError(ProvenanceError):
    """A signing key id was registered twice."""


class UnknownAttestationError(ProvenanceError):
    """Lookup of an attestation that was never issued."""


class UnknownPolicyError(ProvenanceError):
    """Lookup of a policy that was never defined."""


class DuplicatePolicyError(ProvenanceError):
    """A policy id was defined twice."""


class BadDigestError(ProvenanceError):
    """An artifact/material digest that is not a pinned sha256 pin."""


class BadBuilderError(ProvenanceError):
    """A builder id that is not a URI."""


class BadPolicyError(ProvenanceError):
    """A malformed policy definition."""


class MalformedEnvelopeError(ProvenanceError):
    """An envelope that is not a well-formed DSSE-shaped attestation."""


class SeqOrderError(ProvenanceError):
    """Caller seqs did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _check_str(value: Any, what: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise ProvenanceError("%s must be a str, got %r" % (what, type(value).__name__))
    if not allow_empty and not value:
        raise ProvenanceError("%s must not be empty" % what)
    return value


def _check_seq(seq: Any, last: int) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ProvenanceError("seq must be an int, got %r" % (type(seq).__name__,))
    if seq < 0:
        raise ProvenanceError("seq must be non-negative")
    if seq <= last:
        raise SeqOrderError("seq must strictly increase (last=%d, got=%d)" % (last, seq))
    return seq


def _check_digest(value: Any, what: str) -> str:
    value = _check_str(value, what)
    if not _SHA256_RE.fullmatch(value):
        raise BadDigestError("%s must be a sha256 pin (sha256:<64 hex>), got %r"
                             % (what, value))
    return value


def _check_builder(value: Any) -> str:
    value = _check_str(value, "builder id")
    if not _BUILDER_URI_RE.match(value):
        raise BadBuilderError("builder id must be a URI, got %r" % value)
    return value


def _check_level(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProvenanceError("slsa_level must be an int, got %r"
                             % (type(value).__name__,))
    if value not in SLSA_LEVELS:
        raise ProvenanceError("slsa_level must be one of %r, got %r"
                             % (SLSA_LEVELS, value))
    return value


def _check_materials(materials: Any) -> Tuple[Tuple[str, str], ...]:
    if materials is None:
        return ()
    if not isinstance(materials, (list, tuple)):
        raise ProvenanceError("materials must be a list/tuple of (uri, digest) pairs")
    out = []
    for item in materials:
        if (not isinstance(item, (list, tuple)) or len(item) != 2
                or isinstance(item, bool)):
            raise ProvenanceError("material must be a (uri, digest) pair, got %r"
                                  % (item,))
        uri, digest = item
        uri = _check_str(uri, "material uri")
        digest = _check_digest(digest, "material digest")
        out.append((uri, digest))
    out.sort(key=lambda p: p[0])
    return tuple(out)


def _check_external_parameters(params: Any) -> Tuple[Tuple[str, Any], ...]:
    if params is None:
        return ()
    if not isinstance(params, Mapping):
        raise ProvenanceError("external_parameters must be a mapping")
    out = []
    for key, value in params.items():
        key = _check_str(key, "external parameter key")
        _canonical(value)  # fail closed on non-canonicalizable values
        out.append((key, value))
    out.sort(key=lambda kv: kv[0])
    return tuple(out)


def _statement_json(statement: Dict[str, Any]) -> str:
    """Deterministic JSON serialization of a statement (no floats allowed)."""
    return json.dumps(statement, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KeyRecord:
    """A registered signing key (digest-pinned; the secret never appears)."""
    key_id: str
    key_digest: str
    seq: int
    version: str = PROVENANCE_ATTESTOR_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {"key_id": self.key_id, "key_digest": self.key_digest,
                "seq": self.seq, "version": self.version, "schema": self.schema}


@dataclass(frozen=True)
class Attestation:
    """One issued SLSA-shaped attestation (statement + DSSE envelope)."""
    att_id: str
    artifact_name: str
    artifact_digest: str
    statement: Dict[str, Any]
    statement_digest: str
    envelope: Dict[str, Any]
    envelope_digest: str
    key_id: str
    slsa_level: int
    seq: int
    version: str = PROVENANCE_ATTESTOR_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {"att_id": self.att_id, "artifact_name": self.artifact_name,
                "artifact_digest": self.artifact_digest,
                "statement": self.statement,
                "statement_digest": self.statement_digest,
                "envelope": self.envelope,
                "envelope_digest": self.envelope_digest,
                "key_id": self.key_id, "slsa_level": self.slsa_level,
                "seq": self.seq, "version": self.version, "schema": self.schema}

    def verify_digest(self) -> bool:
        """Re-derive the envelope digest pin from the sealed envelope."""
        env = self.envelope
        return _digest_pin("dsse-envelope", env["payloadType"],
                           env["payload"], env["signatures"]) == self.envelope_digest


@dataclass(frozen=True)
class PolicyRecord:
    """The verifier's pinned trust policy."""
    policy_id: str
    trusted_builders: Tuple[str, ...]
    min_slsa_level: int
    expected_source_uri: Optional[str]
    trusted_keys: Tuple[str, ...]
    require_resolved_deps: bool
    policy_digest: str
    seq: int
    version: str = PROVENANCE_ATTESTOR_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {"policy_id": self.policy_id,
                "trusted_builders": list(self.trusted_builders),
                "min_slsa_level": self.min_slsa_level,
                "expected_source_uri": self.expected_source_uri,
                "trusted_keys": list(self.trusted_keys),
                "require_resolved_deps": self.require_resolved_deps,
                "policy_digest": self.policy_digest,
                "seq": self.seq, "version": self.version, "schema": self.schema}


@dataclass(frozen=True)
class VerificationReport:
    """Verdict data from verify(): failures are data, not exceptions."""
    att_id: str
    valid: bool
    reasons: Tuple[str, ...]
    policy_id: Optional[str]
    policy_ok: Optional[bool]
    key_id: str
    statement_digest: str
    seq: int
    version: str = PROVENANCE_ATTESTOR_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {"att_id": self.att_id, "valid": self.valid,
                "reasons": list(self.reasons), "policy_id": self.policy_id,
                "policy_ok": self.policy_ok, "key_id": self.key_id,
                "statement_digest": self.statement_digest,
                "seq": self.seq, "version": self.version, "schema": self.schema}


# ---------------------------------------------------------------------------
# Attestor
# ---------------------------------------------------------------------------

class ProvenanceAttestor:
    """SLSA-shaped provenance ledger: keys, attestations, policies.

    ``register_key`` pins a signing key. ``attest`` seals an in-toto v1
    statement (SLSA provenance v1 predicate) in a DSSE-shaped envelope.
    ``verify`` re-derives pins, checks the signature, and optionally
    evaluates a named policy. ``policy`` pins the verifier's trust.
    """

    def __init__(self, seed: Optional[bytes] = None) -> None:
        if seed is not None and (not isinstance(seed, (bytes, bytearray))
                                 or len(seed) < 16):
            raise ProvenanceError("seed must be bytes of length >= 16")
        self._seed = bytes(seed) if seed is not None else None
        self._lock = threading.RLock()
        self._keys: Dict[str, KeyRecord] = {}
        self._secrets: Dict[str, bytes] = {}
        self._attestations: Dict[str, Attestation] = {}
        self._policies: Dict[str, PolicyRecord] = {}
        self._att_counter = 0
        self._last_seq = -1

    # -- internal ------------------------------------------------------

    def _monotonic(self, seq: int) -> int:
        return _check_seq(seq, self._last_seq)

    def _bump(self, seq: int) -> int:
        seq = self._monotonic(seq)
        self._last_seq = seq
        return seq

    def _derive_secret(self, key_id: str) -> bytes:
        # Deterministic derivation when a seed was supplied (tests); the
        # caller may instead pass an explicit secret at register_key.
        if self._seed is None:
            raise ProvenanceError("no seed configured and no secret supplied "
                                  "for key %r" % key_id)
        return hmac.new(self._seed, b"provenance-attestor:" + key_id.encode("utf-8"),
                        hashlib.sha256).digest()

    # -- keys ----------------------------------------------------------

    def register_key(self, key_id: str, seq: int,
                     secret: Optional[bytes] = None) -> KeyRecord:
        """Pin a signing key id. The secret is stored, never pinned."""
        with self._lock:
            seq = self._bump(seq)
            key_id = _check_str(key_id, "key id")
            if key_id in self._keys:
                raise DuplicateKeyError("key id %r already registered" % key_id)
            if secret is None:
                secret = self._derive_secret(key_id)
            if (not isinstance(secret, (bytes, bytearray)) or len(secret) < 16
                    or len(secret) > 64):
                raise ProvenanceError("secret must be bytes of length 16..64")
            secret = bytes(secret)
            key_digest = _digest_pin("signing-key", key_id, len(secret))
            record = KeyRecord(key_id=key_id, key_digest=key_digest, seq=seq)
            self._keys[key_id] = record
            self._secrets[key_id] = secret
            return record

    def key(self, key_id: str) -> KeyRecord:
        """Read back a key record (metadata only — never the secret)."""
        with self._lock:
            try:
                return self._keys[key_id]
            except KeyError:
                raise UnknownKeyError("unknown key id %r" % key_id)

    def key_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._keys))

    # -- attestation ---------------------------------------------------

    def attest(self, artifact_name: str, artifact_digest: str,
               builder_id: str, build_type: str,
               materials: Optional[Sequence[Tuple[str, str]]],
               seq: int, *, key_id: str, slsa_level: int = 0,
               source_uri: Optional[str] = None,
               invocation_id: Optional[str] = None,
               external_parameters: Optional[Mapping[str, Any]] = None
               ) -> Attestation:
        """Seal an in-toto v1 / SLSA provenance v1 statement in a DSSE
        envelope and sign it. Returns a frozen, digest-pinned record."""
        with self._lock:
            seq = self._bump(seq)
            artifact_name = _check_str(artifact_name, "artifact name")
            artifact_hex = _check_digest(artifact_digest, "artifact digest")[7:]
            builder_id = _check_builder(builder_id)
            build_type = _check_str(build_type, "build type")
            mats = _check_materials(materials)
            slsa_level = _check_level(slsa_level)
            key_id = _check_str(key_id, "key id")
            if key_id not in self._secrets:
                raise UnknownKeyError("unknown key id %r" % key_id)
            if source_uri is not None:
                source_uri = _check_str(source_uri, "source uri")
            if invocation_id is not None:
                invocation_id = _check_str(invocation_id, "invocation id")
            ext_params = _check_external_parameters(external_parameters)

            statement: Dict[str, Any] = {
                "_type": STATEMENT_TYPE,
                "subject": [{
                    "name": artifact_name,
                    "digest": {"sha256": artifact_hex},
                }],
                "predicateType": PREDICATE_TYPE,
                "predicate": {
                    "buildDefinition": {
                        "buildType": build_type,
                        "externalParameters": {k: v for k, v in ext_params},
                        "resolvedDependencies": [
                            {"uri": uri, "digest": {"sha256": d[7:]}}
                            for uri, d in mats
                        ],
                    },
                    "runDetails": {
                        "builder": {"id": builder_id},
                        "metadata": {
                            "invocationId": invocation_id or "",
                            "slsaLevel": slsa_level,
                        },
                    },
                },
            }
            if source_uri is not None:
                statement["predicate"]["buildDefinition"][
                    "externalParameters"]["sourceUri"] = source_uri
            stmt_text = _statement_json(statement)
            statement_digest = _digest_pin("slsa-statement", stmt_text)

            payload_b64 = base64.b64encode(stmt_text.encode("utf-8")).decode("ascii")
            sig = hmac.new(self._secrets[key_id],
                           (PAYLOAD_TYPE + "." + payload_b64).encode("ascii"),
                           hashlib.sha256).hexdigest()
            envelope = {
                "payloadType": PAYLOAD_TYPE,
                "payload": payload_b64,
                "signatures": [{"keyid": key_id, "sig": sig}],
            }
            envelope_digest = _digest_pin("dsse-envelope", PAYLOAD_TYPE,
                                          payload_b64, envelope["signatures"])

            self._att_counter += 1
            att_id = "att-%d" % self._att_counter
            record = Attestation(
                att_id=att_id, artifact_name=artifact_name,
                artifact_digest=artifact_digest, statement=statement,
                statement_digest=statement_digest, envelope=envelope,
                envelope_digest=envelope_digest, key_id=key_id,
                slsa_level=slsa_level, seq=seq)
            self._attestations[att_id] = record
            return record

    def attestation(self, att_id: str) -> Attestation:
        """Read back an issued attestation."""
        with self._lock:
            try:
                return self._attestations[att_id]
            except KeyError:
                raise UnknownAttestationError("unknown attestation %r" % att_id)

    def attestation_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._attestations,
                                key=lambda a: int(a.split("-", 1)[1])))

    # -- policy --------------------------------------------------------

    def policy(self, policy_id: str, seq: int, *,
               trusted_builders: Sequence[str] = (),
               min_slsa_level: int = 0,
               expected_source_uri: Optional[str] = None,
               trusted_keys: Sequence[str] = (),
               require_resolved_deps: bool = False) -> PolicyRecord:
        """Pin the verifier's trust policy. Trusted keys must already be
        registered; builders must be URIs; level is pinned to 0–3."""
        with self._lock:
            seq = self._bump(seq)
            policy_id = _check_str(policy_id, "policy id")
            if policy_id in self._policies:
                raise DuplicatePolicyError("policy %r already defined" % policy_id)
            builders = tuple(_check_builder(b) for b in trusted_builders)
            min_slsa_level = _check_level(min_slsa_level)
            if expected_source_uri is not None:
                expected_source_uri = _check_str(expected_source_uri,
                                                 "expected source uri")
            keys = tuple(_check_str(k, "trusted key id") for k in trusted_keys)
            for k in keys:
                if k not in self._secrets:
                    raise UnknownKeyError("trusted key %r is not registered" % k)
            if not isinstance(require_resolved_deps, bool):
                raise BadPolicyError("require_resolved_deps must be a bool")
            policy_digest = _digest_pin("verify-policy", policy_id, builders,
                                        min_slsa_level, expected_source_uri,
                                        keys, require_resolved_deps)
            record = PolicyRecord(
                policy_id=policy_id, trusted_builders=builders,
                min_slsa_level=min_slsa_level,
                expected_source_uri=expected_source_uri,
                trusted_keys=keys,
                require_resolved_deps=require_resolved_deps,
                policy_digest=policy_digest, seq=seq)
            self._policies[policy_id] = record
            return record

    def get_policy(self, policy_id: str) -> PolicyRecord:
        """Read back a policy record."""
        with self._lock:
            try:
                return self._policies[policy_id]
            except KeyError:
                raise UnknownPolicyError("unknown policy %r" % policy_id)

    # -- verification --------------------------------------------------

    def _verify_signature(self, att: Attestation) -> bool:
        """Re-derive the signature from the sealed envelope."""
        env = att.envelope
        try:
            payload_b64 = env["payload"]
            sigs = env["signatures"]
        except (KeyError, TypeError):
            raise MalformedEnvelopeError("envelope is not DSSE-shaped")
        if env.get("payloadType") != PAYLOAD_TYPE:
            raise MalformedEnvelopeError("unexpected payloadType %r"
                                         % (env.get("payloadType"),))
        if not isinstance(sigs, list) or len(sigs) != 1:
            raise MalformedEnvelopeError("envelope must carry exactly one signature")
        entry = sigs[0]
        try:
            keyid, sig = entry["keyid"], entry["sig"]
        except (KeyError, TypeError):
            raise MalformedEnvelopeError("malformed signature entry")
        secret = self._secrets.get(keyid)
        if secret is None:
            raise UnknownKeyError("envelope signed by unregistered key %r" % keyid)
        expected = hmac.new(secret,
                            (PAYLOAD_TYPE + "." + payload_b64).encode("ascii"),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)

    def verify(self, att_id: str, seq: int,
               policy_name: Optional[str] = None) -> VerificationReport:
        """Verify an attestation: envelope integrity, signature, and
        (optionally) policy conformance. Mismatches are verdict *data* —
        the report's ``valid`` flag is False with reason codes; only a
        structurally malformed envelope raises. This is a pure
        observation view: it validates *seq* but does not consume it and
        writes no audit record."""
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ProvenanceError("seq must be a non-negative int")
        with self._lock:
            try:
                att = self._attestations[att_id]
            except KeyError:
                raise UnknownAttestationError("unknown attestation %r" % att_id)
            reasons: list[str] = []

            # 1. Envelope integrity.
            try:
                envelope_ok = att.verify_digest()
            except Exception:  # pragma: no cover - defensive
                envelope_ok = False
            if not envelope_ok:
                reasons.append("envelope-tampered")

            # 2. Signature.
            key_known = True
            try:
                sig_ok = self._verify_signature(att)
            except UnknownKeyError:
                key_known = False
                sig_ok = False
                reasons.append("unknown-signing-key")
            if key_known and not sig_ok:
                reasons.append("signature-invalid")

            # 3. Statement shape + statement pin.
            stmt = att.statement
            stmt_ok = (
                isinstance(stmt, dict)
                and stmt.get("_type") == STATEMENT_TYPE
                and stmt.get("predicateType") == PREDICATE_TYPE
                and isinstance(stmt.get("subject"), list)
                and len(stmt["subject"]) == 1
            )
            if not stmt_ok:
                reasons.append("statement-malformed")
            elif _digest_pin("slsa-statement", _statement_json(stmt)) \
                    != att.statement_digest:
                reasons.append("statement-tampered")

            # 4. Policy.
            policy_ok: Optional[bool] = None
            policy_id: Optional[str] = None
            if policy_name is not None:
                policy_id = _check_str(policy_name, "policy name")
                try:
                    pol = self._policies[policy_id]
                except KeyError:
                    raise UnknownPolicyError("unknown policy %r" % policy_id)
                policy_ok = True
                pred = stmt.get("predicate", {}) if isinstance(stmt, dict) else {}
                builder = pred.get("runDetails", {}).get("builder", {}).get("id")
                if pol.trusted_builders and builder not in pol.trusted_builders:
                    policy_ok = False
                    reasons.append("builder-untrusted")
                if att.slsa_level < pol.min_slsa_level:
                    policy_ok = False
                    reasons.append("level-too-low")
                ext = pred.get("buildDefinition", {}).get("externalParameters", {})
                if (pol.expected_source_uri is not None
                        and ext.get("sourceUri") != pol.expected_source_uri):
                    policy_ok = False
                    reasons.append("source-uri-mismatch")
                if pol.trusted_keys and att.key_id not in pol.trusted_keys:
                    policy_ok = False
                    reasons.append("key-untrusted")
                if pol.require_resolved_deps:
                    deps = pred.get("buildDefinition", {}).get(
                        "resolvedDependencies", [])
                    if not deps:
                        policy_ok = False
                        reasons.append("no-resolved-dependencies")

            valid = not reasons
            return VerificationReport(
                att_id=att_id, valid=valid, reasons=tuple(reasons),
                policy_id=policy_id, policy_ok=policy_ok, key_id=att.key_id,
                statement_digest=att.statement_digest, seq=seq)


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("key-registered", "attested", "policy-defined",
                "verified", "verification-failed", "rejected")


def provenance_attestor_audit_event(kind: str, seq: int,
                                   **detail: Any) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for attestor activity.

    Carries ids and digest pins only — never key material, never
    statement payloads or material details.
    """
    if kind not in _AUDIT_KINDS:
        raise ProvenanceError("unknown audit kind: %r" % kind)
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ProvenanceError("seq must be a non-negative int")
    banned = {"secret", "payload", "statement", "materials",
              "external_parameters", "externalParameters"}
    for key in detail:
        if key in banned or key.lower().startswith(("secret", "raw_")):
            raise ProvenanceError("audit detail must not carry %r" % key)
    return {
        "schema": AUDIT_SCHEMA,
        "module": "provenance_attestor",
        "moduleVersion": PROVENANCE_ATTESTOR_VERSION,
        "moduleSchema": SCHEMA_PIN,
        "kind": kind,
        "seq": seq,
        "detail": {k: _canonical(v) for k, v in detail.items()},
    }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def main() -> None:
    att = ProvenanceAttestor(seed=b"self-check-seed-0123456789")
    key = att.register_key("ci-key", seq=0)
    assert key.key_digest.startswith("sha256:"), key.key_digest

    digest = "sha256:" + "ab" * 32
    rec = att.attest(
        "widget-1.0.tar.gz", digest,
        "https://github.com/actions/runner@v1",
        "https://slsa.dev/buildType/go@v1",
        [("https://github.com/example/widget", "sha256:" + "cd" * 32)],
        seq=1, key_id="ci-key", slsa_level=2,
        source_uri="https://github.com/example/widget",
        invocation_id="inv-1")
    assert rec.att_id == "att-1", rec.att_id
    assert rec.verify_digest(), "envelope pin must re-derive"

    # Determinism: same inputs on a fresh instance replay identical pins.
    att2 = ProvenanceAttestor(seed=b"self-check-seed-0123456789")
    att2.register_key("ci-key", seq=0)
    rec2 = att2.attest(
        "widget-1.0.tar.gz", digest,
        "https://github.com/actions/runner@v1",
        "https://slsa.dev/buildType/go@v1",
        [("https://github.com/example/widget", "sha256:" + "cd" * 32)],
        seq=1, key_id="ci-key", slsa_level=2,
        source_uri="https://github.com/example/widget",
        invocation_id="inv-1")
    assert rec2.statement_digest == rec.statement_digest
    assert rec2.envelope_digest == rec.envelope_digest

    ok = att.verify("att-1", seq=2)
    assert ok.valid, ok.reasons

    pol = att.policy("prod", seq=3,
                     trusted_builders=["https://github.com/actions/runner@v1"],
                     min_slsa_level=2,
                     expected_source_uri="https://github.com/example/widget",
                     trusted_keys=["ci-key"],
                     require_resolved_deps=True)
    assert pol.policy_digest.startswith("sha256:"), pol.policy_digest
    okp = att.verify("att-1", seq=4, policy_name="prod")
    assert okp.valid and okp.policy_ok, okp.reasons

    # Policy must reject: wrong builder, low level, wrong source, no deps.
    pol2 = att.policy("strict", seq=5,
                      trusted_builders=["https://other.example/builder"],
                      min_slsa_level=3,
                      expected_source_uri="https://other.example/src",
                      trusted_keys=["ci-key"],
                      require_resolved_deps=False)
    bad = att.verify("att-1", seq=6, policy_name="strict")
    assert not bad.valid and not bad.policy_ok, bad.as_dict()
    assert "builder-untrusted" in bad.reasons, bad.reasons
    assert "level-too-low" in bad.reasons, bad.reasons
    assert "source-uri-mismatch" in bad.reasons, bad.reasons

    # Fail-closed edges (each failed mutation consumes its seq).
    for bad_call, exc in [
        (lambda: att.attest("x", "not-a-digest", "https://b/x", "t", [], 7,
                            key_id="ci-key"), BadDigestError),
        (lambda: att.attest("x", digest, "not-a-uri", "t", [], 8,
                            key_id="ci-key"), BadBuilderError),
        (lambda: att.attest("x", digest, "https://b/x", "t", [], 9,
                            key_id="nope"), UnknownKeyError),
        (lambda: att.register_key("ci-key", seq=10), DuplicateKeyError),
        (lambda: att.policy("prod", seq=11), DuplicatePolicyError),
        (lambda: att.verify("att-404", seq=12), UnknownAttestationError),
        (lambda: att.verify("att-1", seq=13, policy_name="nope"),
         UnknownPolicyError),
        (lambda: att.attest("x", digest, "https://b/x", "t", [], 5,
                            key_id="ci-key"), SeqOrderError),
    ]:
        try:
            bad_call()
        except exc:
            pass
        else:
            raise AssertionError("expected %s" % exc.__name__)

    ev = provenance_attestor_audit_event("attested", 9, att_id="att-1",
                                         statement_digest=rec.statement_digest)
    assert ev["schema"] == AUDIT_SCHEMA and ev["moduleVersion"] == PROVENANCE_ATTESTOR_VERSION
    print("provenance-attestor OK: register, attest, verify, policy, refusals")


if __name__ == "__main__":
    main()
