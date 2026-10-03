"""External head anchoring for audit feeds via the Sigstore Rekor transparency log.

Why Rekor (decided 2026-10-03, verified live before writing this module):

* ``https://rekor.sigstore.dev`` answers (``GET /api/v1/log`` → 200, ~4.16M
  entries) and accepts ``POST /api/v1/log/entries`` with **no account, no
  registration, no payment**.
* The v1 API is plain JSON over HTTPS — a minimal, dependency-free client
  fits the repo's offline-first, stdlib-only discipline. RFC 3161 would need
  hand-rolled ASN.1 DER for ``TimeStampReq``/``TimeStampResp`` plus CMS
  signature verification: substantially more code for the same "existed at
  time T" property.
* The 2026 ecosystem direction is Rekor-shaped (PyPI, npm, Homebrew already
  publish there); an independent 2026-04 proof of concept anchored
  Ed25519-signed agent decision receipts to the same public instance.

What is anchored: a DSSE envelope (``dsse`` entry type, v1 API) whose payload
is the canonical JSON anchor statement — feed sha256, head chain hash,
record count. The envelope is signed with the operator's Ed25519 key (the
same vendored ``ed25519`` module the feed signatures use). The PAE
(pre-authentication encoding) follows secure-systems-lab/dsse v1.0.0::

    PAE(type, body) = "DSSEv1" + SP + len(type) + SP + type + SP + len(body) + SP + body

Trust assumptions (also in ``docs/concepts/audit-proof-spec.md``):

1. You trust the Sigstore public-good Rekor operators not to equivocate.
   A compromised log could backdate ``integratedTime``; in practice the
   ecosystem runs witnesses/monitors, but this client does not verify them.
2. The anchor proves *the key holder* pinned *this head* no later than
   ``integratedTime``. It does not prove the feed is complete — an operator
   can anchor a truncated feed. The archive's record count and the hash
   chain mitigate that; the log cannot.
3. ``integratedTime`` is the log's claim, not a qualified timestamp.
   Where eIDAS-style legal weight is needed, use an RFC 3161 TSA instead
   (documented alternative; not implemented here).
4. Only hashes and counts go into the public log — no feed content, no PII.
5. Pinned to the Rekor **v1** API. Sigstore is migrating to a v2
   (rekor-tiles) API; if v1 is retired this module needs a v2 port. The
   anchor record stores ``rekor_api: "v1"`` so verifiers know what spoke it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import textwrap
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REKOR_V1_DEFAULT = "https://rekor.sigstore.dev"
REKOR_API = "v1"
ENTRY_KIND = "dsse"
ENTRY_API_VERSION = "0.0.1"
PAYLOAD_TYPE = "application/vnd.northstar.audit-anchor+json"
ANCHOR_RECORD_VERSION = "northstar-rekor-anchor/1"

# 12-byte DER prefix for an Ed25519 SubjectPublicKeyInfo.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class RekorError(Exception):
    """The transparency log could not be reached or rejected the request.

    Creation-side failures are never silent: callers surface these with a
    dedicated exit code instead of pretending the feed is anchored.
    """


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1.0.0 pre-authentication encoding (the exact bytes signed)."""
    head = f"DSSEv1 {len(payload_type)} {payload_type} ".encode("utf-8")
    return head + b" ".join([str(len(payload)).encode("ascii"), payload])


def ed25519_spki_pem(public_key: bytes) -> str:
    """Encode a 32-byte Ed25519 public key as a PEM SubjectPublicKeyInfo."""
    if len(public_key) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    der = _ED25519_SPKI_PREFIX + public_key
    b64 = base64.b64encode(der).decode("ascii")
    return (
        "-----BEGIN PUBLIC KEY-----\n"
        + "\n".join(textwrap.wrap(b64, 64))
        + "\n-----END PUBLIC KEY-----\n"
    )


def build_envelope(payload: bytes, payload_type: str, signature: bytes) -> dict[str, Any]:
    """Build the DSSE envelope (as a JSON-serialisable dict)."""
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {"keyid": "", "sig": base64.b64encode(signature).decode("ascii")}
        ],
    }


def build_proposal(envelope: dict[str, Any], verifier_pem: str) -> dict[str, Any]:
    """Build the Rekor v1 ``dsse`` proposed entry for an envelope."""
    return {
        "kind": ENTRY_KIND,
        "apiVersion": ENTRY_API_VERSION,
        "spec": {
            "proposedContent": {
                "envelope": json.dumps(envelope),
                "verifiers": [base64.b64encode(verifier_pem.encode("utf-8")).decode("ascii")],
            }
        },
    }


def _post_json(url: str, payload: dict[str, Any], *, timeout: float) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:300]
        raise RekorError(f"rekor rejected the request (HTTP {error.code}): {detail}") from None
    except (OSError, TimeoutError) as error:
        raise RekorError(f"cannot reach {url}: {error}") from None
    except (ValueError, UnicodeDecodeError) as error:
        raise RekorError(f"bad response from {url}: {error}") from None


def submit_entry(
    rekor_url: str,
    proposal: dict[str, Any],
    *,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Submit a proposed entry; return ``{uuid, log_index, integrated_time}``."""
    response = _post_json(f"{rekor_url.rstrip('/')}/api/v1/log/entries", proposal, timeout=timeout)
    if not isinstance(response, dict) or len(response) != 1:
        raise RekorError(f"unexpected submit response shape: {str(response)[:200]}")
    uuid, entry = next(iter(response.items()))
    if not isinstance(entry, dict):
        raise RekorError(f"unexpected submit entry shape: {str(entry)[:200]}")
    try:
        return {
            "uuid": uuid,
            "log_index": int(entry["logIndex"]),
            "integrated_time": int(entry["integratedTime"]),
        }
    except (KeyError, TypeError, ValueError) as error:
        raise RekorError(f"submit response missing log fields: {error}") from None


def retrieve_by_index(
    rekor_url: str,
    log_index: int,
    *,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Fetch the canonical stored entry at a log index.

    Returns the stored entry dict (``body`` is base64 canonical JSON).
    Raises :class:`RekorError` when the log is unreachable or the index
    is absent.
    """
    response = _post_json(
        f"{rekor_url.rstrip('/')}/api/v1/log/entries/retrieve",
        {"logIndexes": [log_index]},
        timeout=timeout,
    )
    if not isinstance(response, list) or not response:
        raise RekorError("rekor returned no entries for the log index")
    first = response[0]
    if not isinstance(first, dict) or len(first) != 1:
        raise RekorError(f"unexpected retrieve response shape: {str(response)[:200]}")
    _uuid, entry = next(iter(first.items()))
    if not isinstance(entry, dict) or "body" not in entry:
        raise RekorError("retrieved entry has no body")
    return entry


def anchor_statement(
    *,
    feed_sha256: str,
    head_chain_hash: str | None,
    records: int,
    anchored_at: str,
) -> bytes:
    """Canonical JSON bytes of the anchor statement (the DSSE payload)."""
    statement = {
        "anchor": ANCHOR_RECORD_VERSION,
        "feed_sha256": feed_sha256,
        "head_chain_hash": head_chain_hash,
        "records": records,
        "anchored_at": anchored_at,
    }
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _rfc3339_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def anchor_feed_head(
    feed: str | Path,
    seed: bytes,
    *,
    rekor_url: str = REKOR_V1_DEFAULT,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Anchor a feed's head hash in the Rekor transparency log.

    Computes the offline head anchor (reusing ``audit_chain``), signs the
    DSSE PAE with ``seed`` (32-byte Ed25519 seed), submits it, and returns
    the anchor record — a self-contained JSON dict the verifier needs.
    Raises :class:`RekorError` on any network/log failure: the caller must
    surface that instead of claiming the feed is anchored.
    """
    from audit_chain import anchor_manifest
    from ed25519 import public_key as ed_public_key
    from ed25519 import sign as ed_sign

    if len(seed) != 32:
        raise ValueError("the Ed25519 seed must be 32 bytes")
    manifest = anchor_manifest(feed)
    head = manifest.get("head_chain_hash")
    if not isinstance(head, str) or not head:
        raise ValueError("feed has no chained head to anchor (is it a chained feed?)")
    payload = anchor_statement(
        feed_sha256=manifest["feed_sha256"],
        head_chain_hash=head,
        records=manifest["records"],
        anchored_at=_rfc3339_now(),
    )
    signature = ed_sign(seed, pae(PAYLOAD_TYPE, payload))
    pubkey = ed_public_key(seed)
    pem = ed25519_spki_pem(pubkey)
    envelope = build_envelope(payload, PAYLOAD_TYPE, signature)
    envelope_bytes = json.dumps(envelope).encode("utf-8")
    submitted = submit_entry(rekor_url, build_proposal(envelope, pem), timeout=timeout)
    return {
        "anchor": ANCHOR_RECORD_VERSION,
        "rekor_url": rekor_url.rstrip("/"),
        "rekor_api": REKOR_API,
        "entry_kind": ENTRY_KIND,
        "uuid": submitted["uuid"],
        "log_index": submitted["log_index"],
        "integrated_time": submitted["integrated_time"],
        "payload_type": PAYLOAD_TYPE,
        "payload": json.loads(payload.decode("utf-8")),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "envelope_sha256": hashlib.sha256(envelope_bytes).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
        "pubkey": pubkey.hex(),
        "trust": "docs/concepts/audit-proof-spec.md#external-anchoring-via-rekor",
    }


def verify_anchor_offline(anchor: dict[str, Any], *, head_chain_hash: str) -> tuple[bool, str]:
    """Offline checks: head consistency + the anchor signature.

    ``head_chain_hash`` is recomputed from the feed under verification.
    Returns ``(ok, note)``; never raises on malformed input.
    """
    try:
        if anchor.get("anchor") != ANCHOR_RECORD_VERSION:
            return False, "not a northstar rekor anchor record"
        payload_dict = anchor["payload"]
        payload = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if hashlib.sha256(payload).hexdigest() != anchor.get("payload_sha256"):
            return False, "anchor payload hash mismatch (anchor record tampered)"
        if payload_dict.get("head_chain_hash") != head_chain_hash:
            return (
                False,
                "anchor pins a different head (feed rewritten or truncated after anchoring)",
            )
        from ed25519 import verify as ed_verify

        pubkey = bytes.fromhex(anchor["pubkey"])
        signature = base64.b64decode(anchor["signature"])
        if not ed_verify(pubkey, pae(anchor.get("payload_type", PAYLOAD_TYPE), payload), signature):
            return False, "anchor DSSE signature invalid (not made by the claimed key)"
        return True, (
            f"anchor signature ok, head {str(head_chain_hash)[:16]}… pinned at "
            f"log index {anchor.get('log_index')}"
        )
    except (KeyError, TypeError, ValueError) as error:
        return False, f"malformed anchor record: {error}"


def verify_anchor_in_log(
    anchor: dict[str, Any],
    *,
    rekor_url: str | None = None,
    timeout: float = 60.0,
) -> tuple[bool, str]:
    """Online check: the entry exists in the public log, unchanged.

    Retrieves the canonical stored entry by log index and compares the
    stored ``payloadHash`` and verifier against the anchor record.
    Raises :class:`RekorError` when the log cannot be reached — the caller
    reports that distinctly instead of silently passing.
    """
    url = (rekor_url or anchor.get("rekor_url") or REKOR_V1_DEFAULT).rstrip("/")
    try:
        log_index = int(anchor["log_index"])
    except (KeyError, TypeError, ValueError):
        return False, "anchor record has no usable log_index"
    entry = retrieve_by_index(url, log_index, timeout=timeout)
    try:
        stored = json.loads(base64.b64decode(entry["body"]).decode("utf-8"))
        spec = stored["spec"]
        payload_hash = spec["payloadHash"]["value"]
        verifier_b64 = spec["signatures"][0]["verifier"]
    except (KeyError, TypeError, ValueError) as error:
        return False, f"stored entry has unexpected shape: {error}"
    if payload_hash != anchor.get("payload_sha256"):
        return False, "log entry payload differs from the anchor (entry replaced?)"
    # The stored verifier is the base64 PEM we submitted; compare against
    # the anchor's pubkey by re-deriving the PEM.
    try:
        stored_pem = base64.b64decode(verifier_b64).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False, "stored verifier is not decodable"
    if ed25519_spki_pem(bytes.fromhex(anchor["pubkey"])) != stored_pem:
        return False, "log entry was anchored by a different key"
    integrated = entry.get("integratedTime")
    return True, (
        f"entry present in public log at index {log_index}"
        + (f", integrated_time {integrated}" if integrated is not None else "")
    )
