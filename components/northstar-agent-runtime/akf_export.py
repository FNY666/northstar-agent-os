"""Export a Northstar audit feed as an AKF v1.1 unit (spike).

AKF — Agent Knowledge Format (MIT, https://github.com/HMAKT99/AKF) — is a
per-artifact provenance metadata format ("every photo has EXIF, every song
has ID3, AKF is the native metadata format for AI-generated content"). Its
``akf audit <file> --regulation eu_ai_act`` consumes ONE AKF unit (a
``.akf`` JSON file or a JSON string) and runs regulation checklists over
it. This module assembles one AKF v1.1 unit whose ``claims`` are the
feed's event records, so the real ``akf`` tool can audit our feed without
us pretending the feed *is* an AKF-native artifact.

This is an **evidence-shape spike, not an AKF conformance claim**:

* The unit is assembled from a chained audit feed (``audit.ndjson/1``),
  i.e. a log-import. Fields Northstar cannot honestly fill are **omitted**,
  never fabricated — see "Honest omissions" below.
* Schema validity (``validate_akf_unit``) never establishes AKF
  conformance; the real check is the ``akf`` package's own
  ``compliance.check_regulation(..., 'eu_ai_act')``, which the test runs
  when the package is importable.
* AKF v1.1 is the pinned target (``spec/akf-v1.1.schema.json`` in the
  upstream repo, commit e4908d3, 2026-10-03). If upstream moves the
  schema, this exporter must be re-validated.

Field mapping (feed record -> AKF unit), all offline, pure software:

* ``v = "1.1"`` — the pinned AKF schema version.
* ``id = "akf:northstar:run/<run-id>"`` (or ``...:session/<session-id>``,
  or the feed filename when neither is known).
* ``label`` — operator-supplied ``--label`` (default ``"internal"``);
  the feed's own data classes are not mapped, so a default is the honest
  choice rather than a guessed classification.
* ``at`` — export time (ISO-8601, UTC); ``by = "northstar-audit-export"``;
  ``agent = "northstar-agent-runtime"`` (the software that produced the
  feed).
* ``hash = "sha256:<feed sha256>"`` — integrity hash of the source feed
  file (AKF ``hash`` pattern: ``^(sha256|sha3-512|blake3):.*$``).
* ``made_by = [{"by": "northstar-audit-export", "role": "system", "at": ...}]``.
* ``prov`` — two hops, with ``do`` verbs drawn from the schema's
  required enum (``created | enriched | reviewed | consumed |
  transformed`` — the official schema rejects anything else):
  ``{"hop": 0, "by": "northstar-agent-runtime", "do": "created",
  "at": <genesis started_ts>, "h": "sha256:<feed>"}`` (the runtime did
  create the feed — factually accurate) and
  ``{"hop": 1, "by": "northstar-audit-export", "do": "transformed",
  "at": <now>}`` (the export transformed the feed into an AKF unit).
  CAVEAT, documented rather than hidden: AKF's ``eu_ai_act``
  human-oversight heuristic passes on
  ``action in ("reviewed", "created") and not actor.startswith("ai-")``,
  so hop 0 makes that check pass on *machine* provenance. The heuristic
  cannot distinguish "software created this" from "a human oversaw
  this" — a real limitation worth knowing before relying on the score.
  ``claim.ver`` / unit ``reviews`` remain absent: no human review is
  tracked, and no verb games that.
* ``claims`` — one per feed record, in feed order:
  ``id = "<event>:<seq>"``; ``c`` = a factual one-line statement of the
  event (event name, seq, and the record's key payload fields such as
  tool / decision / tier); ``t = 1.0`` — record fidelity of a
  deterministic log entry, NOT model confidence (documented in
  ``meta.northstar_akf_spike``); ``ai = false`` — these claims describe
  *logged events*, not AI-generated end-user content, so EU AI Act
  Art. 50-style AI-output labeling does not apply; ``src = "audit.ndjson/1"``
  (the source ledger); ``src_hash = "sha256:<record chain_hash>"`` — each
  claim commits its own record's chain hash.
* ``meta.northstar_akf_spike`` — chain head hash, feed sha256, record
  count, and the confidence/``ai`` semantics notes above, so a reader of
  the unit alone can see exactly what was and was not asserted.
* ``compliance = {"eu_ai_act": "self-assessed/spike"}`` — a marker that
  this unit has NOT passed ``akf audit``; run the real tool for the check.
* ``model`` — only when the operator passes ``--model-id`` (omitted when
  unknown, never guessed).

Honest omissions (fields the feed cannot fill):

* Claim ``ver`` (verified) / unit ``reviews`` — the audit feed tracks no
  human review of events. Note the interaction with the schema-forced
  ``"created"`` prov verb above: AKF's ``eu_ai_human_oversight`` check
  (Art. 14) passes on machine provenance because of the heuristic, so
  the *score* will not surface this gap — the gap is documented here
  and in ``meta.northstar_akf_spike.honest_gaps`` instead of being
  discoverable from the audit output.
* ``sig`` / ``sig_algo`` / ``sig_by`` — the chain is hash-chained, not
  signed per export. (Feed-level Ed25519 signatures exist in
  ``audit_chain.sign_record`` but are not universal; a spike must not
  claim them.)
* ``origin`` per claim — our events are neither human- nor AI-authored
  content; they are machine log entries.

Expected real-tool outcome (verified against the actual
``python/akf/compliance.py`` source, not the docs):

* ``akf audit unit.akf --regulation eu_ai_act``: 4/4 checks pass, score
  1.0, ``compliant=True``. Read the score with the caveat above: the
  Art. 14 human-oversight check passes on the schema-required
  ``"created"`` verb, so a green score does NOT mean a human reviewed
  anything — the feed tracks no human review (``claim.ver`` absent).
* ``akf audit unit.akf`` (general): provenance, integrity hash,
  classification, all-claims-sourced, AI-claims-labeled,
  valid-structure, origin-tracking, freshness pass; ``review_present``
  fails (no reviews — the honest gap the score hides).
"""
from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#: Pinned AKF schema version this exporter targets. Re-validate against
#: upstream (https://github.com/HMAKT99/AKF, spec/akf-v1.1.schema.json)
#: before changing.
AKF_SCHEMA_VERSION = "1.1"

#: Honesty marker for every human-facing description of this export.
AKF_SHAPE_LABEL = "AKF v1.1 unit assembled from a chained audit feed (spike, log-import)"

#: Producer identifier used in ``by`` / ``made_by`` / provenance.
PRODUCER = "northstar-audit-export"

#: The software that produced the source feed.
FEED_PRODUCER = "northstar-agent-runtime"

#: AKF ``label`` classification values (schema enum).
AKF_LABELS = ("public", "internal", "confidential", "highly-confidential", "restricted")

#: Claim confidence semantics: deterministic log-entry fidelity, NOT model
#: confidence. Written into ``meta.northstar_akf_spike`` so the unit is
#: self-describing.
CONFIDENCE_NOTE = (
    "record fidelity of a deterministic log entry, not model confidence"
)

#: ``ai: false`` semantics note.
AI_FALSE_NOTE = (
    "claims describe logged events, not AI-generated end-user content; "
    "EU AI Act Art. 50 AI-output labeling does not apply"
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _claim_statement(record: dict[str, Any], index: int) -> str:
    """One factual line describing a feed record.

    Only fields the record actually carries; nothing inferred.
    """
    event = record.get("event", "?")
    seq = record.get("seq", index)
    bits = [f"{event} #{seq}"]
    for key in ("tool", "decision", "tier", "ok", "level", "component"):
        value = record.get(key)
        if value is not None and not isinstance(value, (dict, list)):
            bits.append(f"{key}={value}")
    return ": ".join(bits)


def _feed_session_ids(first_record: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """(session_id, run_id, started_ts) from the feed's genesis anchor."""
    from audit_chain import feed_genesis_ids

    return feed_genesis_ids(first_record)


def build_akf_unit(
    feed: str | Path,
    *,
    label: str = "internal",
    subject: str | None = None,
    model_id: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    """Assemble one AKF v1.1 unit from a chained audit feed file.

    The feed must be a *chained* audit feed (``northstar audit verify``
    would report OK): the unit commits the chain head by hash, and an
    unchained feed has no head to commit. Raises ``ValueError`` with a
    plain message when the feed is unprotected, broken, or unreadable.
    """
    from audit_chain import anchor_manifest, verify_file

    if label not in AKF_LABELS:
        raise ValueError(f"unknown AKF label {label!r} (expected one of {AKF_LABELS})")
    path = Path(feed)
    try:
        result = verify_file(path)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"cannot read audit feed {path}: {error}") from error
    if result.unprotected:
        raise ValueError(
            f"audit feed {path} is UNPROTECTED (no hash chain): "
            "--akf needs a chained feed, export with --chain first"
        )
    if not result.ok:
        raise ValueError(
            f"audit feed {path} is BROKEN ({result.reason or 'chain mismatch'}): "
            "refusing to export evidence from a tampered feed"
        )
    manifest = anchor_manifest(path)
    head = manifest["head_chain_hash"]
    if not isinstance(head, str) or not head:
        raise ValueError(f"audit feed {path} has chained records but no head hash")
    feed_sha256 = manifest["feed_sha256"]

    import json as _json

    try:
        raw = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError(f"cannot read audit feed {path}: {error}") from error

    records: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if line:
            records.append(_json.loads(line))
    if not records:
        raise ValueError(f"audit feed {path} has no records")

    session_id, run_id, started_ts = _feed_session_ids(records[0])
    stamp = now or _utc_now_iso()
    source_event_id = run_id or session_id or path.name

    claims: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        event = record.get("event", "?")
        seq = record.get("seq", index)
        chain_hash = record.get("chain_hash")
        claim: dict[str, Any] = {
            # Claim content: a factual statement of the logged event.
            "id": f"{event}:{seq}",
            "c": _claim_statement(record, index),
            # t = confidence: 1.0 = deterministic log-entry fidelity.
            "t": 1.0,
            # ai = false: claims describe logged events, not AI output.
            "ai": False,
            # src: the source ledger this claim was transcribed from.
            "src": "audit.ndjson/1",
        }
        if isinstance(chain_hash, str) and chain_hash:
            # Each claim commits its own record's chain hash.
            claim["src_hash"] = "sha256:" + chain_hash
        # Deliberately absent: "ver" (verified) — the feed tracks no human
        # review; "risk" — deterministic gate decisions carry no model
        # confidence; "origin" — machine log entries, not authored content.
        claims.append(claim)

    unit: dict[str, Any] = {
        "v": AKF_SCHEMA_VERSION,
        "id": subject
        or (
            f"akf:northstar:run/{run_id}"
            if run_id
            else (f"akf:northstar:session/{session_id}" if session_id else f"akf:northstar:feed/{path.name}")
        ),
        "label": label,
        "at": stamp,
        "by": PRODUCER,
        "agent": FEED_PRODUCER,
        # Integrity hash of the source feed (AKF hash pattern ^(sha256|...):).
        "hash": "sha256:" + feed_sha256,
        "made_by": [{"by": PRODUCER, "role": "system", "at": stamp}],
        "prov": [
            {
                "hop": 0,
                "by": FEED_PRODUCER,
                # "created": factually accurate (the runtime created the feed)
                # and one of the schema's required ProvHop.do enum values.
                # Caveat: AKF's eu_ai_act human-oversight heuristic keys on
                # ("reviewed", "created") with a non-"ai-" actor, so this
                # honest verb makes that check pass on machine provenance.
                # The heuristic cannot tell "software created this" from
                # "a human oversaw this" — documented, not hidden.
                "do": "created",
                "at": started_ts or stamp,
                "h": "sha256:" + feed_sha256,
            },
            # "transformed": the export transformed the feed into an AKF unit.
            {"hop": 1, "by": PRODUCER, "do": "transformed", "at": stamp},
        ],
        "claims": claims,
        # Marker, not a pass: run `akf audit` for the real check.
        "compliance": {"eu_ai_act": "self-assessed/spike"},
        "meta": {
            "northstar_akf_spike": {
                "shape": AKF_SHAPE_LABEL,
                "chain_head": "sha256:" + head,
                "feed_sha256": "sha256:" + feed_sha256,
                "record_count": len(records),
                "claim_confidence_semantics": CONFIDENCE_NOTE,
                "ai_false_semantics": AI_FALSE_NOTE,
                "source_event_id": source_event_id,
                "honest_gaps": [
                    "no per-claim human review (claim.ver absent) and no "
                    "unit reviews - but note the schema-forced 'created' "
                    "prov verb makes akf's eu_ai_human_oversight heuristic "
                    "pass on machine provenance; the green score must not "
                    "be read as human oversight",
                    "no unit-level signature (sig absent) - hash chain only",
                    "no model identity unless --model-id is passed",
                ],
            }
        },
    }
    if model_id:
        # AKF top-level "model" is a plain string identifier.
        unit["model"] = model_id
    return unit


def validate_akf_unit(unit: Any) -> list[str]:
    """Self-check an exported unit against the AKF v1.1 required shape.

    Returns a list of problem strings (empty = valid). This checks the
    spec's required invariants — ``v``/``claims`` at unit level,
    ``c``/``t`` per claim, ``hop``/``by``/``do``/``at`` per provenance
    hop — plus the types the real ``akf`` package's audit relies on.
    Schema validity alone never establishes AKF conformance; the real
    check is ``akf``'s own ``compliance.check_regulation``.
    """
    problems: list[str] = []
    if not isinstance(unit, dict):
        return ["unit is not an object"]
    if unit.get("v") != AKF_SCHEMA_VERSION:
        problems.append(f"v must be {AKF_SCHEMA_VERSION!r}")
    claims = unit.get("claims")
    if not isinstance(claims, list) or not claims:
        problems.append("claims must be a non-empty array")
    else:
        for i, claim in enumerate(claims):
            where = f"claims[{i}]"
            if not isinstance(claim, dict):
                problems.append(f"{where} is not an object")
                continue
            if not isinstance(claim.get("c"), str) or not claim["c"]:
                problems.append(f"{where}.c (content) must be a non-empty string")
            t = claim.get("t")
            if not isinstance(t, (int, float)) or isinstance(t, bool) or not 0.0 <= t <= 1.0:
                problems.append(f"{where}.t (confidence) must be a number in [0, 1]")
            if claim.get("ai") is not None and not isinstance(claim.get("ai"), bool):
                problems.append(f"{where}.ai must be a boolean when present")
            src = claim.get("src")
            if src is not None and (not isinstance(src, str) or not src):
                problems.append(f"{where}.src must be a non-empty string when present")
    prov = unit.get("prov")
    if not isinstance(prov, list) or not prov:
        problems.append("prov must be a non-empty array")
    else:
        for i, hop in enumerate(prov):
            where = f"prov[{i}]"
            if not isinstance(hop, dict):
                problems.append(f"{where} is not an object")
                continue
            for key in ("hop", "by", "do", "at"):
                if hop.get(key) in (None, ""):
                    problems.append(f"{where}.{key} is required")
    label = unit.get("label")
    if label is not None and label not in AKF_LABELS:
        problems.append(f"label {label!r} not in AKF enum {AKF_LABELS}")
    digest = unit.get("hash")
    if digest is not None:
        import re as _re

        if not isinstance(digest, str) or not _re.match(r"^(sha256|sha3-512|blake3):.*$", digest):
            problems.append("hash must match ^(sha256|sha3-512|blake3):.*$")
    made_by = unit.get("made_by")
    if not isinstance(made_by, list) or not made_by:
        problems.append("made_by must be a non-empty array")
    return problems


def unit_to_json_bytes(unit: dict[str, Any]) -> bytes:
    """JCS canonical bytes of the AKF unit (the digest form)."""
    from audit_chain import jcs_canonical_json

    return jcs_canonical_json(unit)


def unit_sha256(unit: dict[str, Any]) -> str:
    """sha256 hex of the unit's JCS canonical form."""
    return hashlib.sha256(unit_to_json_bytes(unit)).hexdigest()
