"""Export session transcripts as the canonical NDJSON audit feed (audit v1).

The runtime is deliberately dependency-free, so it does not import
``northstar-run-contract.audit``; this module mirrors that envelope spec (the
normative description lives in docs/concepts/audit-trail.md, and the contract
component's ``audit.py`` is the validating implementation for the components
that may depend on it). Both sides pin the same ``AUDIT_SCHEMA_VERSION``.

Each transcript record (``{index, ts, session_id, type, ...payload}``) becomes
one audit line:

* ``event`` = the session record type (``session_start``, ``assistant``,
  ``tool_result``, ``denial``, ``result``, ...);
* ``seq`` = the record's transcript index;
* ``ts`` = the record's original RFC 3339 UTC timestamp (never re-stamped);
* ``level`` = ``error`` for denials, failed tool results and ``error_*``
  results, ``info`` otherwise;
* ``payload`` = everything the transcript record carried beyond the envelope.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from sessions import SESSION_FILE_SUFFIX, load_jsonl, validate_session_id

try:  # the single canonicalizer (SIEM export section below)
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")

AUDIT_SCHEMA_VERSION = "audit.ndjson/1"
COMPONENT = "northstar-agent-runtime"

_ENVELOPE_KEYS = ("index", "ts", "session_id", "type")
_ERROR_TYPES = {"denial"}

#: Envelope rules mirrored from ``northstar-run-contract/audit.py`` (the
#: normative validator). The runtime stays dependency-free, so the rules are
#: duplicated here verbatim instead of imported; ``record_to_audit`` enforces
#: them so the mirror can never emit a record the normative validator would
#: reject (e.g. a feed that ``run-evidence`` would refuse to seal).
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$")
_EVENT_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
_COMPONENT_RE = re.compile(r"^[a-z][a-z0-9-]*$")
_LEVELS: tuple[str, ...] = ("info", "notice", "error")
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
    # docs/concepts/audit-proof-spec.md and audit_chain.py). Mirrors
    # northstar-run-contract/audit.py exactly.
    "prev_hash": str,
    "chain_hash": str,
    "genesis": dict,
    "signature": str,
    "key_id": str,
    # Chain version marker stamped on every v2 record's hashed body
    # ("northstar-audit-chain/2" = JCS canonicalization, IETF-aligned).
    "chain": str,
    # SLSA v1.0-style evidence extension (audit.ndjson/1, optional; see
    # docs/slsa-provenance-mapping.md). Mirrors
    # northstar-run-contract/audit.py exactly, including the
    # externalParameters trust rule.
    "provenance": dict,
    # Hybrid Logical Clock stamp ("<millis>:<counter>", see hlc.py): the
    # causal timestamp that survives multi-writer clock skew. Optional and
    # additive — records written before HLC simply lack it, and the schema
    # stays audit.ndjson/1.
    "hlc": str,
}
#: Trust values a record may assert for its ``externalParameters``.
#: Mirrors northstar-run-contract/audit.py exactly.
_PROVENANCE_TRUST_VALUES = ("untrusted", "verified")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
_HLC_RE = re.compile(r"^(\d+):(\d+)$")


def _record_level(record: dict[str, Any]) -> str:
    """error for denials, failed tool results and error results; else info."""
    kind = record.get("type", "")
    if kind in _ERROR_TYPES:
        return "error"
    if record.get("is_error") is True:
        return "error"
    if kind == "tool_result":
        # Real transcript shape: failed calls carry is_error inside content blocks.
        content = record.get("content")
        if isinstance(content, list) and any(
            isinstance(block, dict) and block.get("is_error") is True for block in content
        ):
            return "error"
    if kind == "result":
        subtype = record.get("subtype")
        if isinstance(subtype, str) and subtype.startswith("error"):
            return "error"
    payload = record.get("payload")
    if isinstance(payload, dict) and payload.get("is_error") is True:
        return "error"
    return "info"


def validate_audit_record(record: Any) -> tuple[str, ...]:
    """Envelope validation errors, mirroring the normative contract validator.

    Empty tuple when the record is valid. Kept in lockstep with
    ``northstar-run-contract/audit.py::validate_record``; the parity test pins
    the two against each other.
    """
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
        or not _COMPONENT_RE.match(record["component"])
    ):
        errors.append("audit 'component' must be a lowercase name like 'northstar-agent-runtime'")
    if "event" in record and (
        not isinstance(record["event"], str) or not _EVENT_RE.match(record["event"])
    ):
        errors.append("audit 'event' must be a non-empty identifier")
    if "ts" in record and (not isinstance(record["ts"], str) or not _TS_RE.match(record["ts"])):
        errors.append("audit 'ts' must be an RFC 3339 UTC timestamp ending in 'Z'")
    if "level" in record and record["level"] not in _LEVELS:
        errors.append(f"audit 'level' must be one of {', '.join(_LEVELS)}")
    if "seq" in record and (
        not isinstance(record["seq"], int)
        or isinstance(record["seq"], bool)
        or record["seq"] < 0
    ):
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

    Verbatim mirror of ``northstar-run-contract/audit.py::_validate_provenance``
    — the runtime stays dependency-free, so the rules are duplicated here and
    pinned by the parity test in tests/test_audit_export.py. Field meanings
    follow docs/slsa-provenance-mapping.md:

    * ``buildType`` — SLSA buildDefinition.buildType: URI naming the
      run-type profile this evidence claims to follow.
    * ``builder.id`` — SLSA runDetails.builder.id: URI identifying the
      builder; self-asserted (see ``selfAsserted``).
    * ``invocationId`` — SLSA runDetails.metadata.invocationId: unique id of
      this run invocation; must match the envelope ``run_id``.
    * ``externalParameters`` — SLSA buildDefinition.externalParameters:
      externally-controlled inputs. SLSA's core rule: a record carrying
      non-empty externalParameters MUST carry ``externalParametersTrust``
      ("untrusted" | "verified"); unmarked external input is a validation
      error, never a silent default.
    * ``internalParameters`` — SLSA buildDefinition.internalParameters:
      builder-set parameters.
    * ``resolvedDependencies`` — SLSA
      buildDefinition.resolvedDependencies: ``[{"uri": ..., "digest":
      {algo: value}}]`` materials the run resolved.
    * ``selfAsserted`` — honesty marker: True means ``builder.id`` is a
      self-report, not a third-party attestation.
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


def build_provenance(
    *,
    build_type: str = "https://northstar.dev/agent-run/v1",
    builder_id: str = "https://northstar.dev/runtime/northstar-agent-runtime",
    invocation_id: str | None = None,
    external_parameters: dict[str, Any] | None = None,
    external_parameters_trust: str = "untrusted",
    internal_parameters: dict[str, Any] | None = None,
    resolved_dependencies: list[dict[str, Any]] | None = None,
    self_asserted: bool = True,
) -> dict[str, Any]:
    """Build the SLSA v1.0-style ``provenance`` object for an audit record.

    This is the constructor side of the mapping in
    docs/slsa-provenance-mapping.md — every argument maps one SLSA v1.0
    provenance field onto the agent-run setting:

    * ``build_type`` — SLSA ``buildDefinition.buildType``: URI naming the
      run-type profile the evidence claims to follow. Selects the verifier's
      expectations, like the build type does in SLSA.
    * ``builder_id`` — SLSA ``runDetails.builder.id``: URI identifying the
      builder. SLSA assumes a *trusted* build platform; here the id is
      self-asserted (``self_asserted=True`` by default), so a verifier must
      cross-check it against the record's Ed25519 ``key_id`` or an external
      anchor before trusting it.
    * ``invocation_id`` — SLSA ``runDetails.metadata.invocationId``: the
      unique id of this run invocation (the audit ``run_id``).
    * ``external_parameters`` — SLSA ``buildDefinition.externalParameters``:
      externally-controlled inputs (user-supplied tool arguments, prompts).
      SLSA's rule is kept: they are untrusted unless the builder verifies
      them, and the verdict is explicit — pass
      ``external_parameters_trust="verified"`` only after the builder
      checked the inputs against a policy. The default "untrusted" is
      emitted as an explicit marking, never left implicit.
    * ``internal_parameters`` — SLSA
      ``buildDefinition.internalParameters``: builder-set parameters (e.g.
      the approval-tier thresholds in effect); trusted only as far as the
      builder is.
    * ``resolved_dependencies`` — SLSA
      ``buildDefinition.resolvedDependencies``: materials the run resolved
      (tool definitions, skill versions, plugin manifests), each
      ``{"uri": ..., "digest": {"sha256": ...}}``.
    * ``self_asserted`` — honesty marker: the Northstar runtime is not a
      hardened SLSA builder, so ``builder.id`` is a self-report. Integrity
      comes from the audit hash chain + optional Ed25519 signature +
      external anchor, not from a third-party attestation.

    The returned object is validated before it leaves: a provenance that
    would fail ``validate_audit_record`` raises ``ValueError`` here.
    """
    if external_parameters_trust not in _PROVENANCE_TRUST_VALUES:
        raise ValueError(
            f"external_parameters_trust must be one of "
            f"{', '.join(_PROVENANCE_TRUST_VALUES)}"
        )
    provenance: dict[str, Any] = {
        "buildType": build_type,
        "builder": {"id": builder_id},
        "externalParametersTrust": external_parameters_trust,
        "selfAsserted": self_asserted,
    }
    if invocation_id is not None:
        provenance["invocationId"] = invocation_id
    if external_parameters is not None:
        provenance["externalParameters"] = dict(external_parameters)
    if internal_parameters is not None:
        provenance["internalParameters"] = dict(internal_parameters)
    if resolved_dependencies is not None:
        provenance["resolvedDependencies"] = [dict(dep) for dep in resolved_dependencies]
    errors = _validate_provenance(provenance)
    if errors:
        raise ValueError(errors[0])
    return provenance


def _valid_hlc_shape(value: Any) -> bool:
    """Wire-shape check for an HLC stamp, mirroring hlc.unpack exactly.

    Kept as a verbatim-duplicated shape rule (like every rule above) so the
    mirror stays in lockstep with northstar-run-contract/audit.py; the
    normative unpack lives in hlc.py.
    """
    if not isinstance(value, str):
        return False
    match = _HLC_RE.fullmatch(value)
    if match is None:
        return False
    return int(match.group(1)) <= (1 << 48) - 1 and int(match.group(2)) <= (1 << 16) - 1


def record_to_audit(record: dict[str, Any]) -> dict[str, Any]:
    """Map one session transcript record to one canonical audit record.

    The mapped record is validated against the envelope spec before it is
    returned: an export must fail loudly here, never emit a line that the
    normative validator (or the evidence sealer) would reject downstream.
    """
    for key in _ENVELOPE_KEYS:
        if key not in record:
            raise ValueError(f"session record is missing {key!r}; not a transcript record?")
    index = record["index"]
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ValueError(f"session record has an invalid index {index!r}; not a transcript record?")
    audit: dict[str, Any] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "component": COMPONENT,
        "event": record["type"],
        "seq": index,
        "ts": record["ts"],
        "level": _record_level(record),
        "payload": {
            key: value
            for key, value in record.items()
            if key not in _ENVELOPE_KEYS and key != "hlc"
        },
    }
    hlc_stamp = record.get("hlc")
    if isinstance(hlc_stamp, str) and hlc_stamp:
        # Top-level causal timestamp (optional, additive); validated below.
        audit["hlc"] = hlc_stamp
    session_id = record.get("session_id")
    if isinstance(session_id, str) and session_id:
        audit["session_id"] = session_id
    errors = validate_audit_record(audit)
    if errors:
        raise ValueError(errors[0])
    return audit


def records_to_ndjson(
    records: Iterable[dict[str, Any]],
    *,
    chain: bool = False,
    session_id: str | None = None,
    run_id: str | None = None,
) -> str:
    """Canonical NDJSON text for whole transcript records (newline-terminated).

    With ``chain=True`` every record is sealed with the tamper-evident hash
    chain (``audit_chain.chain_records``) before serialising; the genesis
    anchor names the session/run the feed claims to describe. Unchained
    output is byte-identical to previous versions.
    """
    audit_records = [record_to_audit(record) for record in records]
    if chain:
        from audit_chain import chain_records as _chain_records

        audit_records = _chain_records(
            audit_records,
            component=COMPONENT,
            session_id=session_id,
            run_id=run_id,
        )
    return "".join(
        json.dumps(
            audit_record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for audit_record in audit_records
    )


def load_jsonl_records(path: Path) -> list[dict[str, Any]]:
    """Transcript records from a ``*.jsonl`` file (torn tail skipped, like the reader)."""
    records, _dropped = load_jsonl(path)
    return records


def transcript_path_to_ndjson(path: Path) -> str:
    """Export one transcript file (``*.jsonl``) as canonical NDJSON audit text.

    Torn trailing lines are skipped exactly like the transcript reader skips
    them (expected after a crash); earlier corruption raises.
    """
    return records_to_ndjson(load_jsonl_records(path))


def session_path(directory: Path, session_id: str) -> Path:
    """The transcript file for one session id (mirrors the session_view lookup)."""
    validate_session_id(session_id)
    return directory / f"{session_id}{SESSION_FILE_SUFFIX}"


# ---------------------------------------------------------------------------
# SIEM export interface: filter, stream, and render audit records for
# collectors (Splunk HEC / Elastic bulk / Sentinel shaped envelopes).
#
# Research note: production SIEM ingestion wants three things from an export
# layer, and this section books each of them as deterministic single-host
# bookkeeping:
#
# * **Filtering** — scope an export once (event kinds, severity levels, a
#   caller-seq window), digest-pin the definition so every later evaluation
#   reproduces the same record set. A filter is a frozen record, not a
#   lambda, so it can be audited and re-verified.
# * **Streaming** — cursor-paginated reads over the ledger in ``(seq,
#   record_id)`` order, so arbitrarily large ledgers export in bounded pages
#   with no wall-clock and no skipped or duplicated records. Cursors are
#   tamper-evident: they carry the pinned filter's digest and are refused if
#   forged or mixed across filters.
# * **SIEM rendering** — envelopes collectors actually parse:
#   newline-delimited JSON, CEF, and LEEF. This books *rendered bundles*,
#   not deliveries: ``delivered=True`` means "the host sink reported
#   success", never "the SIEM indexed it". The sink is host-injectable
#   (``sink(bundle) -> bool``); the default accepts in memory so everything
#   runs without a network.
#
# House style for this section: frozen dataclasses, caller int seqs strictly
# increasing on mutations (reads validate seq shape only and consume
# nothing), RLock-guarded, fail-closed, stdlib-only, ``sha256:`` digest pins,
# ``audit.ndjson/1`` audit events.
#
# Honest scope: every record is host-reported; this pins what it was handed.
# ``kinds`` filters on the payload's ``event`` field and ``severities`` on
# its ``severity`` field — both host-controlled (GIGO). A rendered CEF/LEEF
# line is a *claim* the host asked to be formatted, not proof the underlying
# event happened.
# ---------------------------------------------------------------------------

#: Module version for the SIEM export section.
AUDIT_EXPORT_IFACE_VERSION = "audit-export-siem.v1"

#: Schema pin for records produced by the SIEM export section.
SIEM_SCHEMA_PIN = "northstar.audit-export-siem.v1"

#: Fixed audit vocabulary for the SIEM export section.
_SIEM_AUDIT_KINDS = (
    "record-ingested",
    "filter-defined",
    "filtered",
    "streamed",
    "export-rendered",
    "rejected",
)

#: Pinned severity vocabulary (host-reported; used for filter + CEF/LEEF).
_SIEM_SEVERITIES = ("info", "low", "medium", "high", "critical")

#: CEF numeric severity per level.
_SIEM_SEVERITY_NUM = {"info": 0, "low": 3, "medium": 5, "high": 8, "critical": 10}

#: Pinned SIEM envelope vocabulary.
_SIEM_FORMATS = ("json", "cef", "leef")

#: Stream page size bounds.
_SIEM_MIN_PAGE = 1
_SIEM_MAX_PAGE = 1000


class AuditExportError(Exception):
    """Base error for the SIEM audit export."""


class DuplicateRecordError(AuditExportError):
    """Raised when a record id is ingested twice."""


class UnknownRecordError(AuditExportError):
    """Raised when a record id is not known."""


class UnknownFilterError(AuditExportError):
    """Raised when a filter id is not known."""


class BadFilterError(AuditExportError):
    """Raised for malformed filter definitions."""


class BadCursorError(AuditExportError):
    """Raised for malformed, forged, or cross-filter cursors."""


class BadFormatError(AuditExportError):
    """Raised for unknown SIEM envelope formats."""


class SeqOrderError(AuditExportError):
    """Raised when a mutation seq is not strictly increasing."""


def _siem_check_seq(value: Any, name: str = "seq") -> int:
    """Validate a caller seq (shape only; reads use this)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AuditExportError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise AuditExportError(f"{name} must be non-negative")
    return value


def _siem_check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuditExportError(f"{name} must be a non-empty str")
    return value


def _siem_canonicalize(obj: Any) -> Any:
    """Canonicalize a payload; fail closed on anything unrepresentable."""
    if obj is None or isinstance(obj, (bool, str)):
        return obj
    if isinstance(obj, int):
        if abs(obj) > 2 ** 53:
            raise AuditExportError("int magnitude beyond 2**53 refused (JCS float-loss caveat)")
        return obj
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise AuditExportError("NaN/inf refused")
        if obj.is_integer() and abs(obj) > 2 ** 53:
            raise AuditExportError("integral float magnitude beyond 2**53 refused")
        return obj
    if isinstance(obj, (list, tuple)):
        return [_siem_canonicalize(v) for v in obj]
    if isinstance(obj, Mapping):
        for k in obj:
            if not isinstance(k, str) or not k:
                raise AuditExportError(f"bad mapping key {k!r}")
        return {k: _siem_canonicalize(obj[k]) for k in sorted(obj)}
    raise AuditExportError(f"non-canonicalizable value of type {type(obj).__name__}")


def _siem_digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


def _cef_token(value: Any) -> str:
    """Make a string safe for a CEF pipe-delimited header field."""
    text = str(value)
    for ch in ("|", "\n", "\r", "\\"):
        text = text.replace(ch, " ")
    return text.strip() or "-"


@dataclass(frozen=True)
class StoredRecord:
    """One ingested audit record with its digest pin."""

    record_id: str
    payload: Any
    payload_digest: str
    seq: int
    version: str = AUDIT_EXPORT_IFACE_VERSION
    schema: str = SIEM_SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "payload": self.payload,
            "payload_digest": self.payload_digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; False on any tamper."""
        try:
            return _siem_digest(_siem_canonicalize(self.payload)) == self.payload_digest
        except AuditExportError:
            return False


@dataclass(frozen=True)
class FilterSpec:
    """A pinned filter definition over the ledger."""

    filter_id: str
    kinds: tuple[str, ...]
    severities: tuple[str, ...] | None
    from_seq: int | None
    to_seq: int | None
    spec_digest: str
    seq: int
    version: str = AUDIT_EXPORT_IFACE_VERSION
    schema: str = SIEM_SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "filter_id": self.filter_id,
            "kinds": list(self.kinds),
            "severities": list(self.severities) if self.severities is not None else None,
            "from_seq": self.from_seq,
            "to_seq": self.to_seq,
            "spec_digest": self.spec_digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        try:
            return _siem_digest(_siem_spec_body(self)) == self.spec_digest
        except AuditExportError:
            return False

    def matches(self, record: StoredRecord) -> bool:
        """True iff the record satisfies every pinned criterion.

        ``kinds`` filters on the host-reported ``payload["event"]`` field;
        ``severities`` on ``payload["severity"]`` (a record with no severity
        field does not match a severities-restricted filter).
        """
        if self.kinds and record.payload.get("event") not in self.kinds:
            return False
        if self.severities is not None:
            if record.payload.get("severity") not in self.severities:
                return False
        if self.from_seq is not None and record.seq < self.from_seq:
            return False
        if self.to_seq is not None and record.seq > self.to_seq:
            return False
        return True


def _siem_spec_body(spec: FilterSpec) -> dict[str, Any]:
    return {
        "filter_id": spec.filter_id,
        "kinds": list(spec.kinds),
        "severities": list(spec.severities) if spec.severities is not None else None,
        "from_seq": spec.from_seq,
        "to_seq": spec.to_seq,
    }


@dataclass(frozen=True)
class StreamPage:
    """One cursor-paginated page of filter matches."""

    page_id: str
    filter_id: str
    records: tuple[StoredRecord, ...]
    next_cursor: str | None
    total_matching: int
    page_digest: str
    version: str = AUDIT_EXPORT_IFACE_VERSION
    schema: str = SIEM_SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "page_id": self.page_id,
            "filter_id": self.filter_id,
            "record_ids": [r.record_id for r in self.records],
            "next_cursor": self.next_cursor,
            "total_matching": self.total_matching,
            "page_digest": self.page_digest,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        try:
            body = {
                "page_id": self.page_id,
                "filter_id": self.filter_id,
                "record_ids": [r.record_id for r in self.records],
                "record_digests": [r.payload_digest for r in self.records],
                "next_cursor": self.next_cursor,
                "total_matching": self.total_matching,
            }
            return _siem_digest(_siem_canonicalize(body)) == self.page_digest
        except AuditExportError:
            return False


@dataclass(frozen=True)
class ExportBundle:
    """A SIEM-rendered bundle of filter matches."""

    export_id: str
    filter_id: str
    format: str
    body: str
    body_digest: str
    record_count: int
    delivered: bool
    version: str = AUDIT_EXPORT_IFACE_VERSION
    schema: str = SIEM_SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "export_id": self.export_id,
            "filter_id": self.filter_id,
            "format": self.format,
            "body_digest": self.body_digest,
            "record_count": self.record_count,
            "delivered": self.delivered,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        try:
            return "sha256:" + hashlib.sha256(self.body.encode("utf-8")).hexdigest() == self.body_digest
        except (TypeError, ValueError):
            return False


class AuditExport:
    """Deterministic audit-log export bookkeeping: ingest, filter, stream, render."""

    def __init__(self, sink: Callable[[ExportBundle], bool] | None = None) -> None:
        self._lock = threading.RLock()
        self._records: dict[str, StoredRecord] = {}
        self._order: list[str] = []  # record ids in seq order
        self._filters: dict[str, FilterSpec] = {}
        self._audit_log: list[dict[str, Any]] = []
        self._sink: Callable[[ExportBundle], bool] = sink if sink is not None else (lambda _b: True)
        self._seq = -1
        self._filter_counter = 0
        self._page_counter = 0
        self._export_counter = 0
        self._delivered = 0

    # -- internal ------------------------------------------------------

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(audit_export_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, reason: str) -> None:
        """Burn the seq (batch-21 discipline) and record the rejection."""
        self._seq = _siem_check_seq(seq)
        self._emit("rejected", self._seq, reason=reason)

    def _monotonic(self, seq: int) -> int:
        seq = _siem_check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq must strictly increase (last={self._seq}, got={seq})")
        self._seq = seq
        return seq

    def _matches_ordered(self, spec: FilterSpec) -> list[StoredRecord]:
        return [self._records[rid] for rid in self._order if spec.matches(self._records[rid])]

    # -- mutations ------------------------------------------------------

    def ingest(self, record_id: Any, payload: Any, seq: Any) -> StoredRecord:
        """Book a host-reported audit record."""
        with self._lock:
            try:
                record_id = _siem_check_id(record_id, "record_id")
                if not isinstance(payload, Mapping):
                    raise AuditExportError(f"payload must be a mapping, got {type(payload).__name__}")
                canon = _siem_canonicalize(payload)
                if record_id in self._records:
                    raise DuplicateRecordError(f"duplicate record id {record_id!r}")
                seq = self._monotonic(seq)
            except AuditExportError as exc:
                self._reject(seq if isinstance(seq, int) and not isinstance(seq, bool) else 0,
                             f"ingest:{type(exc).__name__}")
                raise
            rec = StoredRecord(
                record_id=record_id,
                payload=canon,
                payload_digest=_siem_digest(canon),
                seq=seq,
            )
            self._records[record_id] = rec
            self._order.append(record_id)
            self._emit("record-ingested", seq, record_id=record_id,
                       payload_digest=rec.payload_digest)
            return rec

    def define_filter(
        self,
        kinds: Any,
        seq: Any,
        severities: Any = None,
        from_seq: Any = None,
        to_seq: Any = None,
    ) -> FilterSpec:
        """Pin a filter definition; returns the frozen ``FilterSpec``."""
        with self._lock:
            try:
                if not isinstance(kinds, (list, tuple)) or not kinds:
                    raise BadFilterError("kinds must be a non-empty list/tuple")
                kinds_t = tuple(kinds)
                for k in kinds_t:
                    _siem_check_id(k, "kind")
                if len(set(kinds_t)) != len(kinds_t):
                    raise BadFilterError("duplicate kinds refused")
                sev_t: tuple[str, ...] | None = None
                if severities is not None:
                    if not isinstance(severities, (list, tuple)) or not severities:
                        raise BadFilterError("severities must be a non-empty list/tuple or None")
                    sev_t = tuple(severities)
                    for s in sev_t:
                        if s not in _SIEM_SEVERITIES:
                            raise BadFilterError(f"unknown severity {s!r}")
                    if len(set(sev_t)) != len(sev_t):
                        raise BadFilterError("duplicate severities refused")
                fseq = _siem_check_seq(from_seq, "from_seq") if from_seq is not None else None
                tseq = _siem_check_seq(to_seq, "to_seq") if to_seq is not None else None
                if fseq is not None and tseq is not None and fseq > tseq:
                    raise BadFilterError("from_seq must not exceed to_seq")
                seq = self._monotonic(seq)
            except AuditExportError as exc:
                self._reject(seq if isinstance(seq, int) and not isinstance(seq, bool) else 0,
                             f"define_filter:{type(exc).__name__}")
                raise
            self._filter_counter += 1
            filter_id = f"flt-{self._filter_counter}"
            kinds_sorted = tuple(sorted(kinds_t))
            spec = FilterSpec(
                filter_id=filter_id,
                kinds=kinds_sorted,
                severities=sev_t,
                from_seq=fseq,
                to_seq=tseq,
                spec_digest=_siem_digest({
                    "filter_id": filter_id,
                    "kinds": list(kinds_sorted),
                    "severities": list(sev_t) if sev_t is not None else None,
                    "from_seq": fseq,
                    "to_seq": tseq,
                }),
                seq=seq,
            )
            self._filters[filter_id] = spec
            self._emit("filter-defined", seq, filter_id=filter_id,
                       spec_digest=spec.spec_digest)
            return spec

    # -- read views (validate seq shape, consume nothing) -----------------

    def filter(self, filter_id: Any, seq: Any) -> tuple[StoredRecord, ...]:
        """Evaluate a pinned filter; returns all matches in seq order."""
        with self._lock:
            seq = _siem_check_seq(seq)
            spec = self._filters.get(filter_id)
            if spec is None:
                raise UnknownFilterError(f"unknown filter {filter_id!r}")
            matches = self._matches_ordered(spec)
            self._emit("filtered", seq, filter_id=spec.filter_id,
                       spec_digest=spec.spec_digest, match_count=len(matches))
            return tuple(matches)

    def stream(self, filter_id: Any, seq: Any, limit: Any = 100,
               cursor: Any = None) -> StreamPage:
        """Return one cursor-paginated page of filter matches."""
        with self._lock:
            seq = _siem_check_seq(seq)
            spec = self._filters.get(filter_id)
            if spec is None:
                raise UnknownFilterError(f"unknown filter {filter_id!r}")
            if isinstance(limit, bool) or not isinstance(limit, int):
                raise AuditExportError(f"limit must be an int, got {type(limit).__name__}")
            if not (_SIEM_MIN_PAGE <= limit <= _SIEM_MAX_PAGE):
                raise AuditExportError(f"limit must be within [{_SIEM_MIN_PAGE}, {_SIEM_MAX_PAGE}]")
            after = -1
            if cursor is not None:
                after = self._parse_cursor(cursor, spec)
            ordered = self._matches_ordered(spec)
            matches = [r for r in ordered if r.seq > after]
            page_records = tuple(matches[:limit])
            if len(matches) > limit:
                last = page_records[-1]
                next_cursor = f"{spec.filter_id}:{last.seq}:{spec.spec_digest[7:23]}"
            else:
                next_cursor = None
            self._page_counter += 1
            page_id = f"page-{self._page_counter}"
            page = StreamPage(
                page_id=page_id,
                filter_id=spec.filter_id,
                records=page_records,
                next_cursor=next_cursor,
                total_matching=len(ordered),
                page_digest=_siem_digest(_siem_canonicalize({
                    "page_id": page_id,
                    "filter_id": spec.filter_id,
                    "record_ids": [r.record_id for r in page_records],
                    "record_digests": [r.payload_digest for r in page_records],
                    "next_cursor": next_cursor,
                    "total_matching": len(ordered),
                })),
            )
            self._emit("streamed", seq, filter_id=spec.filter_id, page_id=page_id,
                       page_digest=page.page_digest,
                       delivered_count=len(page_records),
                       has_more=next_cursor is not None)
            return page

    def _parse_cursor(self, cursor: Any, spec: FilterSpec) -> int:
        if not isinstance(cursor, str):
            raise BadCursorError("cursor must be a str")
        parts = cursor.split(":")
        if len(parts) != 3 or parts[0] != spec.filter_id:
            raise BadCursorError("cursor does not belong to this filter")
        if parts[2] != spec.spec_digest[7:23]:
            raise BadCursorError("cursor digest does not match the pinned filter")
        try:
            after = int(parts[1])
        except ValueError:
            raise BadCursorError("cursor carries a bad seq")
        if after < 0:
            raise BadCursorError("cursor carries a negative seq")
        return after

    def siem(self, filter_id: Any, seq: Any, format: Any = "json") -> ExportBundle:
        """Render all filter matches into a SIEM envelope and hand to the sink.

        ``format`` is pinned to ``json`` / ``cef`` / ``leef``. Delivery is
        simulated: the host-injectable sink reports success; a raising sink
        counts as failure (fail-closed). The outcome is data, never raised.
        """
        with self._lock:
            seq = _siem_check_seq(seq)
            spec = self._filters.get(filter_id)
            if spec is None:
                raise UnknownFilterError(f"unknown filter {filter_id!r}")
            if format not in _SIEM_FORMATS:
                raise BadFormatError(f"unknown format {format!r}")
            matches = self._matches_ordered(spec)
            body = self._render(format, matches)
            self._export_counter += 1
            bundle = ExportBundle(
                export_id=f"exp-{self._export_counter}",
                filter_id=spec.filter_id,
                format=format,
                body=body,
                body_digest="sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest(),
                record_count=len(matches),
                delivered=False,  # placeholder; replaced below
            )
            try:
                delivered = bool(self._sink(bundle))
            except Exception:
                delivered = False
            bundle = ExportBundle(
                export_id=bundle.export_id,
                filter_id=bundle.filter_id,
                format=bundle.format,
                body=bundle.body,
                body_digest=bundle.body_digest,
                record_count=bundle.record_count,
                delivered=delivered,
            )
            if delivered:
                self._delivered += 1
            self._emit("export-rendered", seq, filter_id=spec.filter_id,
                       export_id=bundle.export_id, format=format,
                       body_digest=bundle.body_digest,
                       record_count=bundle.record_count, delivered=delivered)
            return bundle

    def _render(self, format: str, records: list[StoredRecord]) -> str:
        if format == "json":
            lines = []
            for r in records:
                lines.append(jcs_canonical_json({
                    "schema": SIEM_SCHEMA_PIN,
                    "record": {
                        "id": r.record_id,
                        "seq": r.seq,
                        "digest": r.payload_digest,
                        "payload": r.payload,
                    },
                }).decode("utf-8"))
            return "\n".join(lines)
        if format == "cef":
            lines = []
            for r in records:
                event = _cef_token(r.payload.get("event", r.record_id))
                sev = _SIEM_SEVERITY_NUM.get(str(r.payload.get("severity", "info")), 0)
                lines.append(
                    f"CEF:0|Northstar|AuditExport|1.0|{event}|{event}|{sev}|"
                    f"id={_cef_token(r.record_id)} seq={r.seq} digest={r.payload_digest}"
                )
            return "\n".join(lines)
        # leef
        lines = []
        for r in records:
            event = _cef_token(r.payload.get("event", r.record_id))
            sev = str(r.payload.get("severity", "info"))
            lines.append(
                f"LEEF:2.0|Northstar|AuditExport|1.0|{event}|\t"
                f"sev={_cef_token(sev)}\tid={_cef_token(r.record_id)}\t"
                f"seq={r.seq}\tdigest={r.payload_digest}"
            )
        return "\n".join(lines)

    # -- views -----------------------------------------------------------

    def stored(self, record_id: Any) -> StoredRecord:
        with self._lock:
            rec = self._records.get(record_id)
            if rec is None:
                raise UnknownRecordError(f"unknown record {record_id!r}")
            return rec

    def record_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._order)

    def filter_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._filters)

    def audit_log(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "records": len(self._records),
                "filters": len(self._filters),
                "exports": self._export_counter,
                "delivered": self._delivered,
            }


def audit_export_audit_event(kind: str, seq: int, **detail: Any) -> dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for SIEM export activity.

    Payload values never cross this boundary — only ids, digest pins, and
    counts are carried.
    """
    if kind not in _SIEM_AUDIT_KINDS:
        raise AuditExportError(f"unknown audit kind {kind!r}")
    seq = _siem_check_seq(seq)
    event: dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "event": kind,
        "audit_seq": seq,
        "module_version": AUDIT_EXPORT_IFACE_VERSION,
        "module_schema": SIEM_SCHEMA_PIN,
    }
    event.update({k: _siem_canonicalize(v) for k, v in detail.items()})
    return event


def audit_export_siem_selfcheck() -> None:
    """Self-check for the SIEM export section: ingest, filter, stream, render."""
    exp = AuditExport()
    exp.ingest("r-1", {"event": "granted", "severity": "info"}, 0)
    exp.ingest("r-2", {"event": "denied", "severity": "high"}, 1)
    exp.ingest("r-3", {"event": "granted", "severity": "low"}, 2)
    assert exp.stored("r-1").verify()

    spec = exp.define_filter(["granted"], 3)
    assert spec.verify()
    matches = exp.filter(spec.filter_id, 4)
    assert [r.record_id for r in matches] == ["r-1", "r-3"]

    page = exp.stream(spec.filter_id, 5, limit=1)
    assert [r.record_id for r in page.records] == ["r-1"]
    assert page.next_cursor is not None and page.verify()
    page2 = exp.stream(spec.filter_id, 6, limit=1, cursor=page.next_cursor)
    assert [r.record_id for r in page2.records] == ["r-3"]
    assert page2.next_cursor is None

    sev = exp.define_filter(["granted", "denied"], 7, severities=["high"])
    assert [r.record_id for r in exp.filter(sev.filter_id, 8)] == ["r-2"]

    for fmt, marker in (("json", '"northstar.audit-export-siem.v1"'),
                        ("cef", "CEF:0|Northstar"), ("leef", "LEEF:2.0|Northstar")):
        bundle = exp.siem(spec.filter_id, 9, format=fmt)
        assert marker in bundle.body, fmt
        assert bundle.verify() and bundle.delivered and bundle.record_count == 2

    # Simulated sink failure is data, not an exception.
    def _boom(_bundle: ExportBundle) -> bool:
        raise RuntimeError("collector down")

    flaky = AuditExport(sink=_boom)
    flaky.ingest("x-1", {"event": "granted"}, 0)
    fspec = flaky.define_filter(["granted"], 1)
    failed = flaky.siem(fspec.filter_id, 2)
    assert failed.delivered is False

    stats = exp.stats()
    assert stats["records"] == 3 and stats["exports"] == 3 and stats["delivered"] == 3
    print("audit-export-siem OK: ingest, filter, stream, siem, pins, audit")
