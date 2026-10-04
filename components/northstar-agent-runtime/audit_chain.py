"""Tamper-evident hash chain for the ``audit.ndjson/1`` feed.

A plain NDJSON feed is *self-reported*: nothing stops an operator from
editing history and re-exporting. This module adds an optional,
backward-compatible integrity layer on top of the existing envelope:

* **hash chain** (integrity seal): every chained record carries ``prev_hash``
  and ``chain_hash`` where
  ``chain_hash = sha256(raw(prev_hash) || canonical_json(body))``.
  ``raw(prev_hash)`` is the 32 raw bytes of the hex field; ``body`` is the
  record minus the chain/signature fields (``prev_hash``, ``chain_hash``,
  ``signature``) — ``genesis`` and ``key_id`` stay inside the hashed body.
  The first record's ``prev_hash`` is the *genesis hash*:
  ``sha256(canonical_json(genesis_params))``, and the genesis params object
  is stored on that record so a verifier can recompute it. Any edit,
  deletion or reorder of a chained record breaks every later link.

* **Ed25519 signature** (non-repudiation, optional): ``signature`` covers
  ``canonical_json(record minus signature)`` — i.e. it seals the chain
  fields too, binding the signature to the record's chain position.

Honest vocabulary, enforced by the docs: the hash chain is an *integrity
seal*, not a digital signature. The chain detects *modification* of a feed
whose genesis/anchor the verifier already trusts; it does **not** stop an
operator from rewriting history wholesale and starting a fresh chain —
that needs an external head anchor (see ``anchor_manifest`` and the proof
spec). Signatures add non-repudiation ("this key holder produced this
record") on top of the chain, not instead of it.

``canonical_json`` is byte-identical to the feed's canonical NDJSON line
(sort_keys, no whitespace, UTF-8): a third party that implements the proof
spec reproduces the exact bytes hashed here.

Chain versions: ``northstar-audit-chain/1`` (legacy canonicalization) and
``northstar-audit-chain/2`` (JCS per RFC 8785, aligned with
draft-sharif-agent-audit-trail §6.1). The version is stamped on the genesis
anchor and on every v2 record's hashed body; verifiers dispatch on it, so
v1 feeds verify forever. See docs/concepts/ietf-audit-trail-alignment.md
for the item-by-item comparison with the IETF draft.

Everything here is offline and deterministic. No network, no clock reads:
timestamps only ever come from the records themselves.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

#: Version of the chain construction described here and in the proof spec.
CHAIN_VERSION = "northstar-audit-chain/1"

#: Second chain version: identical topology to v1, but the canonicalization
#: is the JSON Canonicalization Scheme (JCS, RFC 8785) instead of the
#: legacy sort_keys/compact form — this is the alignment with
#: draft-sharif-agent-audit-trail §6.1, which mandates JCS and forbids
#: alternatives. New chains default to v2; v1 feeds keep verifying via
#: version dispatch on the genesis anchor (see docs/concepts/
#: ietf-audit-trail-alignment.md).
CHAIN_VERSION_V2 = "northstar-audit-chain/2"

_CHAIN_VERSIONS = (CHAIN_VERSION, CHAIN_VERSION_V2)

#: Envelope fields that are *excluded* from the hashed body (they are the
#: seal itself, or the signature over the seal).
_SEAL_FIELDS = ("prev_hash", "chain_hash", "signature")

_HEX64_RE = __import__("re").compile(r"^[0-9a-f]{64}$")


def canonical_json(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no whitespace, UTF-8.

    Byte-identical to one NDJSON feed line for the same record.

    This is the *legacy* (chain v1) canonicalization. It is close to JCS
    but not JCS: keys sort by Unicode code point instead of UTF-16 code
    units (the two orders diverge for astral characters), and float
    formatting follows Python repr rather than the specified ECMAScript
    ``Number.prototype.toString`` (they coincide on every RFC 8785
    Appendix B vector, but only JCS is specified). Kept forever so v1
    feeds keep verifying; new code must use :func:`jcs_canonical_json`.
    """
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# JCS (RFC 8785) — delegated to the canonical_json module.
#
# The JCS implementation used to live here. It had a real spec bug: it
# emitted ``\\u000a`` for newline, contradicting RFC 8785 §3.2.2.3, which
# mandates the short escapes \\b \\t \\n \\f \\r. The single implementation
# now lives in ``canonical_json`` (written from the RFC text, pinned by
# RFC golden vectors); this function keeps its signature so every caller
# (trace_export, akf_export, audit_scitt, chain v2) is unaffected.
# ---------------------------------------------------------------------------

from canonical_json import JcsError as JcsError  # noqa: E402,F401
from canonical_json import jcs_canonical_json as _jcs_impl  # noqa: E402


def jcs_canonical_json(obj: Any) -> bytes:
    """JSON Canonicalization Scheme (RFC 8785) bytes, UTF-8.

    This is the canonicalization mandated by
    draft-sharif-agent-audit-trail §6.1 ("Implementations MUST use JCS;
    alternative canonicalization schemes MUST NOT be used"). Used for all
    hashing and signing in ``northstar-audit-chain/2``.

    Implemented in :mod:`canonical_json`; this wrapper preserves the
    historic import location.
    """
    return _jcs_impl(obj)


def _canon_for_version(chain_version: str):
    """Canonicalization function for a chain version (v1 legacy, v2 JCS)."""
    if chain_version == CHAIN_VERSION_V2:
        return jcs_canonical_json
    return canonical_json


def _version_of_record(record: Any) -> str:
    """Chain version governing a record's canonicalization.

    v2 chains stamp every record's hashed body with
    ``"chain": "northstar-audit-chain/2"``; v1 records carry no stamp
    (frozen), so a missing/unknown marker means v1 and old feeds keep
    verifying. The genesis anchor's own ``"chain"`` field is the fallback
    for the first record.
    """
    if isinstance(record, dict):
        if record.get("chain") == CHAIN_VERSION_V2:
            return CHAIN_VERSION_V2
        genesis = record.get("genesis")
        if isinstance(genesis, dict) and genesis.get("chain") == CHAIN_VERSION_V2:
            return CHAIN_VERSION_V2
    return CHAIN_VERSION


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def feed_genesis_ids(first_record: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """(session_id, run_id, started_ts) from a feed's genesis anchor.

    Shared by the export modules (trace/akf) so the genesis parsing lives
    in one place, next to ``build_genesis_params``.
    """
    genesis = first_record.get("genesis")
    if not isinstance(genesis, dict):
        return None, None, None
    session_id = genesis.get("session_id")
    run_id = genesis.get("run_id")
    started_ts = genesis.get("started_ts")
    return (
        session_id if isinstance(session_id, str) and session_id else None,
        run_id if isinstance(run_id, str) and run_id else None,
        started_ts if isinstance(started_ts, str) and started_ts else None,
    )


def build_genesis_params(
    component: str,
    *,
    session_id: str | None = None,
    run_id: str | None = None,
    started_ts: str | None = None,
    chain_version: str = CHAIN_VERSION_V2,
) -> dict[str, Any]:
    """The anchor object stored on the first chained record.

    It binds the chain to the run/session the feed claims to describe, so a
    verifier that *expects* a particular run can cross-check the anchor
    instead of trusting a rewritten history's fresh chain. At least one of
    ``session_id``/``run_id`` should be given; ``started_ts`` pins the run's
    start time when the producer knows it.

    ``chain_version`` selects the canonicalization the chain will use
    (v1 legacy or v2 JCS); it is stored as ``params["chain"]`` so verifiers
    dispatch on it.
    """
    if chain_version not in _CHAIN_VERSIONS:
        raise ValueError(f"unknown chain version {chain_version!r}")
    params: dict[str, Any] = {
        "chain": chain_version,
        "schema_version": "audit.ndjson/1",
        "component": component,
    }
    if session_id is not None:
        params["session_id"] = session_id
    if run_id is not None:
        params["run_id"] = run_id
    if started_ts is not None:
        params["started_ts"] = started_ts
    return params


def genesis_hash(params: dict[str, Any]) -> str:
    """The genesis hash: ``sha256(canon(genesis_params))`` (hex).

    The canonicalization is dispatched on ``params["chain"]`` so v1
    anchors keep hashing the legacy way and v2 anchors use JCS.
    """
    canon = _canon_for_version(_version_of_record(params))
    return _sha256_hex(canon(params))


def chain_record(record: dict[str, Any], prev_hash: str, *, chain_version: str = CHAIN_VERSION) -> dict[str, Any]:
    """Return a copy of ``record`` sealed with ``prev_hash``/``chain_hash``.

    ``chain_hash = sha256(raw(prev_hash) || canon(body))`` where ``body``
    is the record minus the seal/signature fields and ``canon`` is the
    chain version's canonicalization (v1 legacy, v2 JCS per RFC 8785).
    """
    if chain_version not in _CHAIN_VERSIONS:
        raise ValueError(f"unknown chain version {chain_version!r}")
    if not _HEX64_RE.match(prev_hash):
        raise ValueError("prev_hash must be 64 lowercase hex characters")
    canon = _canon_for_version(chain_version)
    chained = dict(record)
    for key in _SEAL_FIELDS:
        chained.pop(key, None)
    body = {k: v for k, v in chained.items() if k not in _SEAL_FIELDS}
    chained["prev_hash"] = prev_hash
    chained["chain_hash"] = _sha256_hex(bytes.fromhex(prev_hash) + canon(body))
    return chained


def chain_records(
    records: list[dict[str, Any]],
    *,
    component: str,
    session_id: str | None = None,
    run_id: str | None = None,
    started_ts: str | None = None,
    key_id: str | None = None,
    chain_version: str = CHAIN_VERSION_V2,
) -> list[dict[str, Any]]:
    """Seal a whole record list; the first record carries the genesis anchor.

    ``key_id`` (when the feed will later be signed) is baked into every
    record's hashed body here: adding it at sign time would change the body
    the chain already sealed.

    ``chain_version`` defaults to v2 (JCS canonicalization, IETF-aligned);
    pass ``CHAIN_VERSION`` explicitly for the legacy v1 construction.
    """
    if not records:
        return []
    if chain_version not in _CHAIN_VERSIONS:
        raise ValueError(f"unknown chain version {chain_version!r}")
    if key_id is not None and (not key_id or len(key_id) > 200):
        raise ValueError("key_id must be a non-empty string of at most 200 characters")
    anchor = build_genesis_params(
        component, session_id=session_id, run_id=run_id,
        started_ts=started_ts if started_ts is not None else records[0].get("ts"),
        chain_version=chain_version,
    )
    genesis = genesis_hash(anchor)
    chained: list[dict[str, Any]] = []
    prev = genesis
    for index, record in enumerate(records):
        if index == 0:
            # The anchor is part of the hashed body: a verifier recomputes
            # the identical bytes (see verify_lines).
            record = {**record, "genesis": anchor}
        if key_id is not None:
            record = {**record, "key_id": key_id}
        if chain_version == CHAIN_VERSION_V2:
            # Self-describing records: the version rides inside the hashed
            # body, so any single record tells a verifier which
            # canonicalization to use. v1 records are unstamped (frozen).
            record = {**record, "chain": chain_version}
        sealed = chain_record(record, prev, chain_version=chain_version)
        chained.append(sealed)
        prev = sealed["chain_hash"]
    return chained


def sign_record(record: dict[str, Any], secret_key: bytes, *, key_id: str | None = None) -> dict[str, Any]:
    """Return a copy of ``record`` with an Ed25519 ``signature``.

    The signature covers ``canon(record minus signature)`` — chain first,
    then sign, so the signature binds the record to its chain position.
    ``canon`` is the record's chain version canonicalization (v1 legacy,
    v2 JCS), dispatched on the genesis anchor; like
    draft-sharif-agent-audit-trail §6.2, the signature is computed over the
    canonical bytes of the record with the signature-value field removed.
    ``secret_key`` is the 32-byte Ed25519 seed.

    ``key_id`` names the signing key for key management. On a chained
    record it must already be in the hashed body (pass it to
    ``chain_records``); adding it now would break the sealed chain, so that
    is a loud ``ValueError``, not a silent re-seal.
    """
    from ed25519 import sign

    signed = dict(record)
    existing = signed.get("key_id")
    if key_id is not None:
        if not key_id or len(key_id) > 200:
            raise ValueError("key_id must be a non-empty string of at most 200 characters")
        if existing is not None and existing != key_id:
            raise ValueError(f"record already carries key_id {existing!r}")
        if "chain_hash" in signed and existing is None:
            raise ValueError("key_id must be baked in at chain time for chained records")
        signed["key_id"] = key_id
    canon = _canon_for_version(_version_of_record(signed))
    signed.pop("signature", None)
    signed["signature"] = sign(secret_key, canon(signed)).hex()
    return signed


def verify_signature(record: dict[str, Any], public_key: bytes) -> bool:
    """Check a record's Ed25519 signature; False when absent or invalid.

    The canonicalization is dispatched on the record's genesis anchor
    (v1 legacy, v2 JCS) so signatures made under either version verify.
    """
    from ed25519 import verify

    signature = record.get("signature")
    if not isinstance(signature, str):
        return False
    try:
        sig_bytes = bytes.fromhex(signature)
    except ValueError:
        return False
    canon = _canon_for_version(_version_of_record(record))
    body = {k: v for k, v in record.items() if k != "signature"}
    return verify(public_key, canon(body), sig_bytes)


def generate_keypair() -> tuple[bytes, bytes]:
    """Fresh (secret_seed, public_key); the seed needs os.urandom, nothing else."""
    seed = os.urandom(32)
    from ed25519 import public_key

    return seed, public_key(seed)


@dataclass
class ChainResult:
    """Outcome of verifying one feed file. Mirrors OrcaI's ChainResult shape."""

    ok: bool
    broken_at: int | None = None  # 1-based physical line number of the first bad link
    records: int = 0  # non-blank lines examined
    chained: int = 0  # records carrying a chain_hash
    unprotected: bool = False  # no chain fields at all: verify reports, never crashes
    reason: str = ""
    signature_failures: list[int] = field(default_factory=list)
    anchor_ok: bool | None = None  # None when no anchor manifest was checked
    #: True when this result came from a strict-mode run (--strict).
    strict_mode: bool = False
    #: The strict violation kind when strict mode failed, else "":
    #: "unparseable-timestamp" | "timestamp-regression" | "duplicate-nonce" |
    #: "invalid-nonce".
    strict_violation: str = ""
    #: The causality violation kind when the HLC check failed, else "":
    #: "causality-inversion". Set by default verify (not strict-only): the
    #: check is structural — a child's HLC stamp must not precede its
    #: parent's — and involves no wall clock, so feeds that verify today
    #: keep verifying (records without a parseable "hlc" stamp are skipped).
    causality_violation: str = ""

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.ok


def _iter_records(lines: Iterable[str]) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield (physical_line_number, parsed_json) for non-blank lines."""
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue
        yield number, json.loads(line)


def verify_lines(
    lines: Iterable[str],
    *,
    public_key: bytes | None = None,
    expect_session_id: str | None = None,
    expect_run_id: str | None = None,
    strict: bool = False,
    clock_skew_seconds: float = 300.0,
) -> ChainResult:
    """Verify a feed's hash chain (and signatures when ``public_key`` is given).

    A feed with no chain fields at all verifies as *unprotected*
    (``ok=False, unprotected=True``) — old exports keep working, loudly
    labelled. A feed where *some* records lack chain fields is broken at the
    first unchained line: a chain with a hole is not a chain.

    On top of the chain, default verify also enforces **causal order** via
    HLC stamps (see ``hlc.py``): for every adjacent parent→child pair that
    both carry a parseable ``"hlc"`` stamp, the child's stamp must not be
    lexicographically smaller than the parent's — a smaller child stamp
    means the producer's timestamps contradict the causal order the chain
    records (the multi-writer inversion HLC exists to prevent). Pairs where
    either record lacks a parseable stamp are skipped, so feeds written
    before HLC (or by producers that do not stamp) verify exactly as
    before.

    ``strict=True`` is opt-in and changes what counts as verified: on top of
    the chain it also enforces timestamp monotonicity (a record may
    regress at most ``clock_skew_seconds`` behind the previous record) and
    nonce deduplication (records carrying a ``nonce`` field must not repeat
    it — the draft-sharif-agent-audit-trail §6.3 rule). Default verify
    semantics are untouched; old feeds that pass today still pass.
    """
    if clock_skew_seconds < 0:
        raise ValueError("clock_skew_seconds must be >= 0")
    records: list[tuple[int, dict[str, Any]]] = []
    try:
        for number, record in _iter_records(lines):
            if not isinstance(record, dict):
                return ChainResult(ok=False, broken_at=number, reason=f"line {number} is not a JSON object")
            records.append((number, record))
    except json.JSONDecodeError as error:
        return ChainResult(ok=False, broken_at=None, reason=f"line is not valid JSON: {error}")

    if not records:
        return ChainResult(ok=False, reason="feed is empty")
    if not any("chain_hash" in record for _, record in records):
        return ChainResult(ok=False, unprotected=True, records=len(records),
                           reason="feed carries no chain fields (unprotected legacy feed)")

    prev_chain: str | None = None
    chained = 0
    sig_failures: list[int] = []
    # Previous record's parsed HLC stamp for the causality check; None
    # until a record with a parseable stamp is seen.
    prev_hlc: tuple[int, int] | None = None
    from hlc import unpack as _hlc_unpack
    # The chain version is a feed-wide property, stamped on every v2
    # record's body and on the genesis anchor; the first record decides.
    canon = _canon_for_version(_version_of_record(records[0][1]))
    for position, (number, record) in enumerate(records):
        chain_hash = record.get("chain_hash")
        prev_hash = record.get("prev_hash")
        if not isinstance(chain_hash, str) or not _HEX64_RE.match(chain_hash):
            return ChainResult(ok=False, broken_at=number, records=len(records), chained=chained,
                               reason=f"line {number}: missing or malformed chain_hash (chain interrupted)")
        if not isinstance(prev_hash, str) or not _HEX64_RE.match(prev_hash):
            return ChainResult(ok=False, broken_at=number, records=len(records), chained=chained,
                               reason=f"line {number}: missing or malformed prev_hash")
        if position == 0:
            genesis = record.get("genesis")
            if not isinstance(genesis, dict):
                return ChainResult(ok=False, broken_at=number, records=len(records), chained=chained,
                                   reason=f"line {number}: first chained record must carry the genesis anchor")
            if genesis_hash(genesis) != prev_hash:
                return ChainResult(ok=False, broken_at=number, records=len(records), chained=chained,
                                   reason=f"line {number}: genesis anchor does not match prev_hash")
            if expect_session_id is not None and genesis.get("session_id") != expect_session_id:
                return ChainResult(ok=False, broken_at=number, records=len(records), chained=chained,
                                   reason=f"line {number}: genesis session_id {genesis.get('session_id')!r} "
                                          f"!= expected {expect_session_id!r}")
            if expect_run_id is not None and genesis.get("run_id") != expect_run_id:
                return ChainResult(ok=False, broken_at=number, records=len(records), chained=chained,
                                   reason=f"line {number}: genesis run_id {genesis.get('run_id')!r} "
                                          f"!= expected {expect_run_id!r}")
        elif prev_hash != prev_chain:
            return ChainResult(ok=False, broken_at=number, records=len(records), chained=chained,
                               reason=f"line {number}: prev_hash does not link to the previous chain_hash "
                                      f"(reorder or splice)")
        body = {k: v for k, v in record.items() if k not in _SEAL_FIELDS}
        expected = _sha256_hex(bytes.fromhex(prev_hash) + canon(body))
        if expected != chain_hash:
            return ChainResult(ok=False, broken_at=number, records=len(records), chained=chained,
                               reason=f"line {number}: chain_hash mismatch (record modified after sealing)")
        prev_chain = chain_hash
        chained += 1
        trust_error = _check_provenance_trust(record)
        if trust_error is not None:
            return ChainResult(ok=False, broken_at=number, records=len(records), chained=chained,
                               reason=f"line {number}: {trust_error}")
        # Causal-order check (HLC): the child's stamp must not precede the
        # parent's. Tuples compare lexicographically, which is the HLC
        # order. Unparseable stamps mean "no HLC information" and skip the
        # pair — this keeps pre-HLC feeds verifying unchanged.
        hlc_now = _hlc_unpack(record.get("hlc"))
        if hlc_now is not None and prev_hlc is not None and hlc_now < prev_hlc:
            return ChainResult(
                ok=False, broken_at=number, records=len(records), chained=chained,
                reason=f"line {number}: causality inversion: hlc stamp "
                       f"{record['hlc']!r} precedes the previous record's "
                       f"stamp (timestamps contradict the chain's causal order)",
                causality_violation="causality-inversion",
            )
        if hlc_now is not None:
            prev_hlc = hlc_now
        if "signature" in record:
            if public_key is None:
                return ChainResult(ok=False, broken_at=number, records=len(records), chained=chained,
                                   reason=f"line {number}: record is signed but no public key was given")
            if not verify_signature(record, public_key):
                sig_failures.append(number)

    if sig_failures:
        first = sig_failures[0]
        return ChainResult(ok=False, broken_at=first, records=len(records), chained=chained,
                           reason=f"line {first}: Ed25519 signature invalid",
                           signature_failures=sig_failures)
    if strict:
        hit = _check_strict(records, clock_skew_seconds=clock_skew_seconds)
        if hit is not None:
            number, violation, strict_reason = hit
            return ChainResult(ok=False, broken_at=number, records=len(records),
                               chained=chained, reason=strict_reason,
                               strict_mode=True, strict_violation=violation)
    return ChainResult(ok=True, records=len(records), chained=chained,
                       reason=f"chain intact over {chained} records"
                              + (" (strict mode)" if strict else ""),
                       strict_mode=strict)


_TS_RE_STRICT = __import__("re").compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?Z$"
)


def _check_provenance_trust(record: dict[str, Any]) -> str | None:
    """SLSA v1.0's core verifier rule, enforced on the audit feed.

    A record carrying non-empty ``provenance.externalParameters`` (external,
    unverified inputs) must mark ``externalParametersTrust`` explicitly as
    "untrusted" or "verified" — unmarked external input is treated as a
    feed integrity problem, not a silent default. Returns the reason string
    when the marking is missing or invalid, else None.

    This is deliberately a small standalone check rather than a call into
    ``audit_export``: ``audit_chain`` stays importable without the export
    module (no import cycle), and ``verify`` must judge feeds that were
    hand-crafted or produced by other components, not only records the
    local ``build_provenance`` helper emitted. The full shape validation
    still lives in ``audit_export.validate_audit_record`` and the normative
    ``northstar-run-contract/audit.py::validate_record``.
    """
    provenance = record.get("provenance")
    if not isinstance(provenance, dict):
        return None
    external = provenance.get("externalParameters")
    if not isinstance(external, dict) or not external:
        return None
    trust = provenance.get("externalParametersTrust")
    if trust not in ("untrusted", "verified"):
        return (
            "provenance carries non-empty 'externalParameters' without an explicit "
            "'externalParametersTrust' marking ('untrusted' | 'verified'): "
            "unmarked external input must fail verification, never pass silently"
        )
    return None


def _parse_audit_ts(ts: Any) -> float | None:
    """Epoch seconds for an ``audit.ndjson/1`` ``ts``; None when missing/malformed.

    Accepts exactly the envelope's timestamp shape (RFC 3339 UTC ending in
    ``Z``, optional millisecond fraction); calendar-invalid values
    (month 13, …) also return None.
    """
    if not isinstance(ts, str):
        return None
    match = _TS_RE_STRICT.fullmatch(ts)
    if match is None:
        return None
    parts = [int(match.group(i)) for i in range(1, 7)]
    millis = int(match.group(7)) if match.group(7) else 0
    try:
        moment = datetime(*parts, millis * 1000, tzinfo=timezone.utc)
    except ValueError:
        return None
    return moment.timestamp()


def _check_strict(
    records: list[tuple[int, dict[str, Any]]],
    *,
    clock_skew_seconds: float,
) -> tuple[int, str, str] | None:
    """Strict-mode verifier extras (opt-in via ``verify --strict``).

    Beyond the hash chain — which already covers the draft's
    ``parent_record_id`` linkage (``prev_hash``) and, with ``--anchor``,
    tail completeness — this enforces the remaining §6.3 verifier rules:

    * **timestamp monotonicity**: ``ts`` must be non-decreasing, allowing a
      regression of at most ``clock_skew_seconds`` for clock skew between
      the producer's clock and reality;
    * **nonce deduplication**: the draft's "nonces must not repeat",
      checked opportunistically on records that carry a ``nonce`` field
      (the audit.ndjson/1 envelope does not mandate one).

    Returns ``(line_number, violation, reason)`` for the first violation,
    or None when the feed passes. Everything is offline and deterministic.
    """
    prev_epoch: float | None = None
    prev_ts: str | None = None
    seen_nonces: dict[Any, int] = {}
    for number, record in records:
        ts = record.get("ts")
        epoch = _parse_audit_ts(ts)
        if epoch is None:
            return (number, "unparseable-timestamp",
                    f"line {number}: strict mode: timestamp {ts!r} is missing or "
                    f"not a valid RFC 3339 UTC 'Z' timestamp")
        if prev_epoch is not None and epoch < prev_epoch - clock_skew_seconds:
            regression = prev_epoch - epoch
            return (number, "timestamp-regression",
                    f"line {number}: strict mode: timestamp regressed "
                    f"{regression:.3f}s ({prev_ts} -> {ts}), exceeding the "
                    f"allowed clock skew of {clock_skew_seconds:g}s")
        prev_epoch, prev_ts = epoch, ts
        nonce = record.get("nonce")
        if nonce is not None:
            try:
                hash(nonce)
            except TypeError:
                return (number, "invalid-nonce",
                        f"line {number}: strict mode: nonce must be a scalar, "
                        f"got {type(nonce).__name__}")
            if nonce in seen_nonces:
                return (number, "duplicate-nonce",
                        f"line {number}: strict mode: duplicate nonce {nonce!r} "
                        f"(first seen at line {seen_nonces[nonce]})")
            seen_nonces[nonce] = number
    return None


def verify_file(path: str | Path, **kwargs: Any) -> ChainResult:
    """Verify a feed file on disk; unreadable files report, never raise."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return verify_lines(handle, **kwargs)
    except OSError as error:
        return ChainResult(ok=False, reason=f"cannot read {path}: {error}")
    except UnicodeDecodeError as error:
        return ChainResult(ok=False, reason=f"{path} is not valid UTF-8: {error}")


def anchor_manifest(
    path: str | Path,
    *,
    anchored_at: str | None = None,
) -> dict[str, Any]:
    """Build the minimal offline head anchor for a feed file.

    The manifest pins ``feed_sha256`` (whole file bytes), ``head_chain_hash``
    and ``records`` so a verifier holding the manifest — stored somewhere the
    feed operator cannot rewrite, e.g. WORM storage or a transparency log —
    detects wholesale rewrites and tail truncation, which the bare chain
    cannot. Shipping the manifest to an external timestamp (RFC 3161) or
    transparency log (Rekor) is the documented next step; this function is
    the offline half and needs no network.
    """
    raw = Path(path).read_bytes()
    head: str | None = None
    records = 0
    for _number, record in _iter_records(raw.decode("utf-8").splitlines()):
        records += 1
        chain_hash = record.get("chain_hash")
        if isinstance(chain_hash, str):
            head = chain_hash
    manifest: dict[str, Any] = {
        "anchor": "northstar-audit-anchor/1",
        "chain": CHAIN_VERSION,
        "feed_sha256": hashlib.sha256(raw).hexdigest(),
        "head_chain_hash": head,
        "records": records,
    }
    if anchored_at is not None:
        manifest["anchored_at"] = anchored_at
    return manifest


def check_anchor(path: str | Path, manifest: dict[str, Any]) -> tuple[bool, str]:
    """Check a feed file against a previously built anchor manifest."""
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        return False, f"cannot read {path}: {error}"
    if manifest.get("anchor") != "northstar-audit-anchor/1":
        return False, "not a northstar audit anchor manifest"
    if hashlib.sha256(raw).hexdigest() != manifest.get("feed_sha256"):
        return False, "feed bytes differ from the anchored snapshot (modified or truncated)"
    head: str | None = None
    records = 0
    try:
        for _number, record in _iter_records(raw.decode("utf-8").splitlines()):
            records += 1
            chain_hash = record.get("chain_hash")
            if isinstance(chain_hash, str):
                head = chain_hash
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return False, f"feed is not readable: {error}"
    if head != manifest.get("head_chain_hash"):
        return False, "head chain_hash differs from the anchor (rewritten history)"
    if records != manifest.get("records"):
        return False, f"record count {records} != anchored {manifest.get('records')} (truncated or extended)"
    return True, f"anchor matches: {records} records, head {str(head)[:16]}…"
