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

Everything here is offline and deterministic. No network, no clock reads:
timestamps only ever come from the records themselves.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

#: Version of the chain construction described here and in the proof spec.
CHAIN_VERSION = "northstar-audit-chain/1"

#: Envelope fields that are *excluded* from the hashed body (they are the
#: seal itself, or the signature over the seal).
_SEAL_FIELDS = ("prev_hash", "chain_hash", "signature")

_HEX64_RE = __import__("re").compile(r"^[0-9a-f]{64}$")


def canonical_json(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no whitespace, UTF-8.

    Byte-identical to one NDJSON feed line for the same record.
    """
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_genesis_params(
    component: str,
    *,
    session_id: str | None = None,
    run_id: str | None = None,
    started_ts: str | None = None,
) -> dict[str, Any]:
    """The anchor object stored on the first chained record.

    It binds the chain to the run/session the feed claims to describe, so a
    verifier that *expects* a particular run can cross-check the anchor
    instead of trusting a rewritten history's fresh chain. At least one of
    ``session_id``/``run_id`` should be given; ``started_ts`` pins the run's
    start time when the producer knows it.
    """
    params: dict[str, Any] = {
        "chain": CHAIN_VERSION,
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
    """The genesis hash: ``sha256(canonical_json(genesis_params))`` (hex)."""
    return _sha256_hex(canonical_json(params))


def chain_record(record: dict[str, Any], prev_hash: str) -> dict[str, Any]:
    """Return a copy of ``record`` sealed with ``prev_hash``/``chain_hash``.

    ``chain_hash = sha256(raw(prev_hash) || canonical_json(body))`` where
    ``body`` is the record minus the seal/signature fields.
    """
    if not _HEX64_RE.match(prev_hash):
        raise ValueError("prev_hash must be 64 lowercase hex characters")
    chained = dict(record)
    for key in _SEAL_FIELDS:
        chained.pop(key, None)
    body = {k: v for k, v in chained.items() if k not in _SEAL_FIELDS}
    chained["prev_hash"] = prev_hash
    chained["chain_hash"] = _sha256_hex(bytes.fromhex(prev_hash) + canonical_json(body))
    return chained


def chain_records(
    records: list[dict[str, Any]],
    *,
    component: str,
    session_id: str | None = None,
    run_id: str | None = None,
    started_ts: str | None = None,
    key_id: str | None = None,
) -> list[dict[str, Any]]:
    """Seal a whole record list; the first record carries the genesis anchor.

    ``key_id`` (when the feed will later be signed) is baked into every
    record's hashed body here: adding it at sign time would change the body
    the chain already sealed.
    """
    if not records:
        return []
    if key_id is not None and (not key_id or len(key_id) > 200):
        raise ValueError("key_id must be a non-empty string of at most 200 characters")
    anchor = build_genesis_params(
        component, session_id=session_id, run_id=run_id,
        started_ts=started_ts if started_ts is not None else records[0].get("ts"),
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
        sealed = chain_record(record, prev)
        chained.append(sealed)
        prev = sealed["chain_hash"]
    return chained


def sign_record(record: dict[str, Any], secret_key: bytes, *, key_id: str | None = None) -> dict[str, Any]:
    """Return a copy of ``record`` with an Ed25519 ``signature``.

    The signature covers ``canonical_json(record minus signature)`` — chain
    first, then sign, so the signature binds the record to its chain
    position. ``secret_key`` is the 32-byte Ed25519 seed.

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
    signed.pop("signature", None)
    signed["signature"] = sign(secret_key, canonical_json(signed)).hex()
    return signed


def verify_signature(record: dict[str, Any], public_key: bytes) -> bool:
    """Check a record's Ed25519 signature; False when absent or invalid."""
    from ed25519 import verify

    signature = record.get("signature")
    if not isinstance(signature, str):
        return False
    try:
        sig_bytes = bytes.fromhex(signature)
    except ValueError:
        return False
    body = {k: v for k, v in record.items() if k != "signature"}
    return verify(public_key, canonical_json(body), sig_bytes)


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
) -> ChainResult:
    """Verify a feed's hash chain (and signatures when ``public_key`` is given).

    A feed with no chain fields at all verifies as *unprotected*
    (``ok=False, unprotected=True``) — old exports keep working, loudly
    labelled. A feed where *some* records lack chain fields is broken at the
    first unchained line: a chain with a hole is not a chain.
    """
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
        expected = _sha256_hex(bytes.fromhex(prev_hash) + canonical_json(body))
        if expected != chain_hash:
            return ChainResult(ok=False, broken_at=number, records=len(records), chained=chained,
                               reason=f"line {number}: chain_hash mismatch (record modified after sealing)")
        prev_chain = chain_hash
        chained += 1
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
    return ChainResult(ok=True, records=len(records), chained=chained,
                       reason=f"chain intact over {chained} records")


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
