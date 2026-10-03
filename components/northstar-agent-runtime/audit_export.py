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

import json
import re
from pathlib import Path
from typing import Any, Iterable

from sessions import SESSION_FILE_SUFFIX, load_jsonl, validate_session_id

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
}
#: Trust values a record may assert for its ``externalParameters``.
#: Mirrors northstar-run-contract/audit.py exactly.
_PROVENANCE_TRUST_VALUES = ("untrusted", "verified")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")


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
        "payload": {key: value for key, value in record.items() if key not in _ENVELOPE_KEYS},
    }
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
