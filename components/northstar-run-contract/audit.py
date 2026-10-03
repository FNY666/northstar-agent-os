"""Canonical audit feed: NDJSON v1 envelope shared by every Northstar producer.

The audit feed is the machine boundary between the repository's append-only
records and a SIEM/analytics pipeline: each line is one self-describing,
versioned record whose envelope is validated strictly (unknown envelope fields
are rejected, so adding a field is a schema revision, not a silent drift).

Producers and their mapping entry points:

* ``northstar-agent-runtime`` - ``audit_export.py`` mirrors this envelope
  locally (the runtime is intentionally dependency-free) and exports session
  transcripts; normative spec: docs/concepts/audit-trail.md.
* ``northstar-durable-run`` - ``durable_audit.event_to_audit`` maps EventStore
  events.
* ``northstar-host`` - ``host_audit.authorization_to_audit`` maps signed
  authorization grants.

Envelope v1 (``audit.ndjson/1``):

* required: ``schema_version``, ``component``, ``event``, ``ts`` (RFC 3339
  UTC, second or millisecond precision, ``Z`` suffix), ``level``
  (``info`` | ``notice`` | ``error``), ``payload`` (object).
* optional: ``seq`` (non-negative int), ``session_id``/``run_id``/``actor_id``
  (strings), and the tamper-evidence extension: ``prev_hash``/``chain_hash``
  (64 lowercase hex chars), ``genesis`` (anchor object, first chained record
  only), ``signature`` (128 hex chars, Ed25519), ``key_id`` (string). The
  chain extension is optional *within* ``audit.ndjson/1`` so legacy feeds
  without it still validate; see docs/concepts/audit-proof-spec.md.
* optional: ``provenance`` (object) — SLSA v1.0-style evidence for the
  event (builder identity, invocation id, external/verified parameters,
  resolved dependencies). SLSA semantics are borrowed, not its trust model:
  ``builder.id`` here is self-asserted (see ``selfAsserted``), the chain
  and signatures carry the integrity. See
  docs/slsa-provenance-mapping.md for the field-by-field mapping.

No other keys are allowed.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Iterable, Iterator

AUDIT_SCHEMA_VERSION = "audit.ndjson/1"

LEVELS: tuple[str, ...] = ("info", "notice", "error")

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$")
_ID_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
_REQUIRED: dict[str, type] = {
    "schema_version": str,
    "component": str,
    "event": str,
    "ts": str,
    "level": str,
    "payload": dict,
}
_OPTIONAL: dict[str, type] = {
    "seq": int,
    "session_id": str,
    "run_id": str,
    "actor_id": str,
    # Tamper-evidence extension (audit.ndjson/1, optional; see
    # docs/concepts/audit-proof-spec.md and audit_chain.py).
    "prev_hash": str,
    "chain_hash": str,
    "genesis": dict,
    "signature": str,
    "key_id": str,
    # Chain version marker stamped on every v2 record's hashed body
    # ("northstar-audit-chain/2" = JCS canonicalization, IETF-aligned).
    "chain": str,
    # SLSA v1.0-style evidence extension (optional object; see
    # docs/slsa-provenance-mapping.md). Deep-validated by
    # _validate_provenance, including the externalParameters trust rule:
    # externally-controlled inputs must carry an explicit trust marking.
    "provenance": dict,
    # Hybrid Logical Clock stamp ("<millis>:<counter>", see the runtime's
    # hlc.py): the causal timestamp that survives multi-writer clock skew.
    # Optional and additive — records written before HLC simply lack it,
    # and the schema stays audit.ndjson/1.
    "hlc": str,
}

#: Trust values a record may assert for its ``externalParameters``. SLSA v1.0
#: treats externalParameters as untrusted by definition; Northstar keeps the
#: same default but requires the producer to say so out loud: a record that
#: carries external inputs without an explicit marking fails validation
#: instead of silently inheriting "untrusted".
_PROVENANCE_TRUST_VALUES = ("untrusted", "verified")

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
_HLC_RE = re.compile(r"^(\d+):(\d+)$")


def _valid_hlc_shape(value: Any) -> bool:
    """Wire-shape check for an HLC stamp: "<millis>:<counter>" with millis
    in 48 bits and counter in 16 bits. Mirrors the runtime mirror's rule
    verbatim (see northstar-agent-runtime/audit_export.py)."""
    if not isinstance(value, str):
        return False
    match = _HLC_RE.fullmatch(value)
    if match is None:
        return False
    return int(match.group(1)) <= (1 << 48) - 1 and int(match.group(2)) <= (1 << 16) - 1


def now_rfc3339(*, now: float | None = None) -> str:
    """RFC 3339 UTC timestamp with milliseconds, e.g. ``2026-09-07T03:04:05.123Z``."""
    seconds = time.time() if now is None else now
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds))
    return f"{base}.{int((seconds % 1) * 1000):03d}Z"


def rfc3339_from_epoch(epoch_seconds: int) -> str:
    """Convert an integer epoch-seconds timestamp into the feed's RFC 3339 form."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(int(epoch_seconds))) + ".000Z"


def new_record(
    component: str,
    event: str,
    *,
    seq: int | None = None,
    ts: str | None = None,
    level: str = "info",
    payload: dict[str, Any] | None = None,
    session_id: str | None = None,
    run_id: str | None = None,
    actor_id: str | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one audit record; raises ``ValueError`` on the first validation error."""
    record: dict[str, Any] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "component": component,
        "event": event,
        "ts": ts if ts is not None else now_rfc3339(),
        "level": level,
        "payload": dict(payload or {}),
    }
    if seq is not None:
        record["seq"] = seq
    for key, value in (
        ("session_id", session_id),
        ("run_id", run_id),
        ("actor_id", actor_id),
    ):
        if value is not None:
            record[key] = value
    if provenance is not None:
        record["provenance"] = dict(provenance)
    errors = validate_record(record)
    if errors:
        raise ValueError(errors[0])
    return record


def validate_record(record: Any) -> tuple[str, ...]:
    """Envelope validation errors (empty tuple when the record is valid)."""
    if not isinstance(record, dict):
        return ("audit record must be an object",)
    errors: list[str] = []
    unknown = sorted(set(record) - set(_REQUIRED) - set(_OPTIONAL))
    if unknown:
        errors.append(f"unknown audit envelope fields: {', '.join(unknown)}")
    for key, expected in _REQUIRED.items():
        if key not in record:
            errors.append(f"audit record is missing {key!r}")
        elif not isinstance(record[key], expected):
            errors.append(f"audit {key!r} must be {expected.__name__}")
    for key, expected in _OPTIONAL.items():
        if key in record and not isinstance(record[key], expected):
            errors.append(f"audit {key!r} must be {expected.__name__}")
    if "schema_version" in record and record["schema_version"] != AUDIT_SCHEMA_VERSION:
        errors.append(
            f"unsupported audit schema_version {record['schema_version']!r} "
            f"(this reader accepts {AUDIT_SCHEMA_VERSION!r} only)"
        )
    if "component" in record and (
        not isinstance(record["component"], str)
        or not re.match(r"^[a-z][a-z0-9-]*$", record["component"])
    ):
        errors.append("audit 'component' must be a lowercase name like 'northstar-agent-runtime'")
    if "event" in record and (
        not isinstance(record["event"], str) or not _ID_RE.match(record["event"])
    ):
        errors.append("audit 'event' must be a non-empty identifier")
    if "ts" in record and (not isinstance(record["ts"], str) or not _TS_RE.match(record["ts"])):
        errors.append("audit 'ts' must be an RFC 3339 UTC timestamp ending in 'Z'")
    if "level" in record and record["level"] not in LEVELS:
        errors.append(f"audit 'level' must be one of {', '.join(LEVELS)}")
    if "seq" in record and (not isinstance(record["seq"], int) or isinstance(record["seq"], bool) or record["seq"] < 0):
        errors.append("audit 'seq' must be a non-negative integer")
    for key in ("session_id", "run_id", "actor_id"):
        if key in record and (
            not isinstance(record[key], str) or not record[key] or len(record[key]) > 200
        ):
            errors.append(f"audit {key!r} must be a non-empty string of at most 200 characters")
    for key in ("prev_hash", "chain_hash"):
        if key in record and (
            not isinstance(record[key], str) or not _HEX64_RE.match(record[key])
        ):
            errors.append(f"audit {key!r} must be 64 lowercase hex characters")
    if "signature" in record and (
        not isinstance(record["signature"], str) or not _HEX128_RE.match(record["signature"])
    ):
        errors.append("audit 'signature' must be 128 lowercase hex characters (Ed25519)")
    if "key_id" in record and (
        not isinstance(record["key_id"], str) or not record["key_id"] or len(record["key_id"]) > 200
    ):
        errors.append("audit 'key_id' must be a non-empty string of at most 200 characters")
    if "provenance" in record:
        errors.extend(_validate_provenance(record["provenance"]))
        # The provenance's invocationId names the same run the envelope
        # names; a mismatch means the evidence is attached to the wrong
        # run and the verifier must not trust it.
        invocation_id = record["provenance"].get("invocationId") if isinstance(record["provenance"], dict) else None
        if (
            isinstance(invocation_id, str)
            and invocation_id
            and isinstance(record.get("run_id"), str)
            and record["run_id"] != invocation_id
        ):
            errors.append(
                f"provenance 'invocationId' {invocation_id!r} does not match "
                f"envelope 'run_id' {record['run_id']!r}"
            )
    if "hlc" in record and not _valid_hlc_shape(record["hlc"]):
        errors.append(
            "audit 'hlc' must be '<millis>:<counter>' with millis in 48 bits "
            "and counter in 16 bits (e.g. '1727865600000:3')"
        )
    return tuple(errors)


def _validate_provenance(provenance: Any) -> tuple[str, ...]:
    """Deep validation for the SLSA v1.0-style ``provenance`` envelope field.

    Field meanings follow the mapping in docs/slsa-provenance-mapping.md;
    every rule below mirrors SLSA v1.0's own verifier obligations, adapted
    to the audit-event setting:

    * ``buildType`` (SLSA buildDefinition.buildType): URI naming the
      run-type profile the evidence claims to follow. The verifier selects
      its expectations by it, so it must be present and non-empty when
      provenance is carried.
    * ``builder.id`` (SLSA runDetails.builder.id): URI identifying the
      builder. Self-asserted here (see ``selfAsserted``), so the verifier
      must cross-check it against the record's Ed25519 ``key_id`` or an
      external anchor before trusting it.
    * ``invocationId`` (SLSA runDetails.metadata.invocationId): the unique
      id of this run invocation; must match the envelope's ``run_id`` when
      both are present.
    * ``externalParameters`` (SLSA buildDefinition.externalParameters):
      externally-controlled inputs (e.g. user-supplied tool arguments).
      SLSA's core rule, enforced here: the verifier MUST NOT treat them as
      trustworthy. A record carrying non-empty externalParameters MUST
      carry ``externalParametersTrust`` ("untrusted" | "verified") —
      unmarked external input is a validation error, never a silent
      default.
    * ``internalParameters`` (SLSA buildDefinition.internalParameters):
      builder-set parameters; trusted only as far as the builder is.
    * ``resolvedDependencies`` (SLSA
      buildDefinition.resolvedDependencies): materials the run resolved,
      each ``{"uri": ..., "digest": {algo: value}}``.
    * ``selfAsserted``: honesty marker — True means ``builder.id`` is a
      self-report, not a third-party attestation; integrity comes from the
      hash chain + optional Ed25519 signature + external anchor.
    """
    errors: list[str] = []
    if not isinstance(provenance, dict):
        return ("audit 'provenance' must be an object",)
    unknown = sorted(set(provenance) - {
        "buildType", "builder", "invocationId", "externalParameters",
        "externalParametersTrust", "internalParameters",
        "resolvedDependencies", "selfAsserted",
    })
    if unknown:
        errors.append(f"unknown provenance fields: {', '.join(unknown)}")
    build_type = provenance.get("buildType")
    if not isinstance(build_type, str) or not build_type or len(build_type) > 500:
        errors.append("provenance 'buildType' must be a non-empty URI string of at most 500 characters")
    builder = provenance.get("builder")
    if builder is not None:
        builder_id = builder.get("id") if isinstance(builder, dict) else None
        if not isinstance(builder_id, str) or not builder_id or len(builder_id) > 500:
            errors.append("provenance 'builder.id' must be a non-empty URI string of at most 500 characters")
    invocation_id = provenance.get("invocationId")
    if invocation_id is not None and (
        not isinstance(invocation_id, str) or not invocation_id or len(invocation_id) > 200
    ):
        errors.append("provenance 'invocationId' must be a non-empty string of at most 200 characters")
    external = provenance.get("externalParameters")
    if external is not None:
        if not isinstance(external, dict):
            errors.append("provenance 'externalParameters' must be an object")
        elif external:
            # SLSA's core verifier rule: external inputs are untrusted until
            # the builder says otherwise, and the saying must be explicit.
            trust = provenance.get("externalParametersTrust")
            if trust not in _PROVENANCE_TRUST_VALUES:
                errors.append(
                    "provenance carrying non-empty 'externalParameters' must mark "
                    "'externalParametersTrust' as one of "
                    f"{', '.join(_PROVENANCE_TRUST_VALUES)} "
                    "(unmarked external input is untrusted input)"
                )
    trust_only = provenance.get("externalParametersTrust")
    if trust_only is not None and trust_only not in _PROVENANCE_TRUST_VALUES:
        errors.append(
            f"provenance 'externalParametersTrust' must be one of "
            f"{', '.join(_PROVENANCE_TRUST_VALUES)}"
        )
    internal = provenance.get("internalParameters")
    if internal is not None and not isinstance(internal, dict):
        errors.append("provenance 'internalParameters' must be an object")
    deps = provenance.get("resolvedDependencies")
    if deps is not None:
        if not isinstance(deps, list):
            errors.append("provenance 'resolvedDependencies' must be an array")
        else:
            for index, dep in enumerate(deps):
                if not isinstance(dep, dict):
                    errors.append(f"provenance 'resolvedDependencies[{index}]' must be an object")
                    continue
                uri = dep.get("uri")
                if not isinstance(uri, str) or not uri or len(uri) > 500:
                    errors.append(
                        f"provenance 'resolvedDependencies[{index}].uri' must be a "
                        "non-empty string of at most 500 characters"
                    )
                digest = dep.get("digest")
                if digest is not None and (
                    not isinstance(digest, dict)
                    or not digest
                    or any(not isinstance(k, str) or not isinstance(v, str) or not v
                           for k, v in digest.items())
                ):
                    errors.append(
                        f"provenance 'resolvedDependencies[{index}].digest' must be a "
                        "non-empty object mapping algorithm names to digest strings"
                    )
    self_asserted = provenance.get("selfAsserted")
    if self_asserted is not None and not isinstance(self_asserted, bool):
        errors.append("provenance 'selfAsserted' must be a boolean")
    return tuple(errors)


def dumps_record(record: dict[str, Any]) -> str:
    """One canonical NDJSON line (no trailing newline); validates first."""
    errors = validate_record(record)
    if errors:
        raise ValueError(errors[0])
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def to_ndjson(records: Iterable[dict[str, Any]]) -> str:
    """Canonical NDJSON text for many records (each line ends with a newline)."""
    return "".join(dumps_record(record) + "\n" for record in records)


def iter_ndjson(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Parse NDJSON text lines into validated audit records.

    Blank lines are skipped; a damaged line raises ``ValueError`` naming the
    line number - an audit feed must fail loudly, never silently drop records.
    """
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"audit line {number} is not valid JSON: {error}") from error
        errors = validate_record(record)
        if errors:
            raise ValueError(f"audit line {number} is invalid: {errors[0]}")
        yield record
