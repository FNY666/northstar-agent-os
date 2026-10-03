"""SCITT (RFC 9943) / COSE Receipts (RFC 9942) export spike for audit feeds.

**Scope: spike, not a feature.** This module answers one question: what would
it take for a Northstar audit feed (``audit.ndjson/1`` + ``northstar-audit-chain/2``)
to be expressed as a SCITT Signed Statement with COSE Receipts, and is the
standard worth tracking for the long-term shape of ``audit export`` and Rekor
anchoring?

The module is dependency-free (stdlib only, like the rest of the runtime).
There is no CBOR/COSE library in the repo, so the structures are emitted as
a **JSON diagnostic representation** of the RFC 9943 §6.1 and RFC 9942 §4
CDDL — every integer label below is the exact label from those sections, and
``docs/scitt-spike.md`` carries the field-by-field mapping with honest gaps.
Nothing here claims to be a conformant SCITT message or a real COSE receipt.

Why this spike matters (from the actual RFCs, read 2026-10-03):

* RFC 9943 defines a *single-issuer signed statement transparency*
  architecture: an Issuer signs a statement about an artifact (COSE_Sign1,
  ``application/scitt-statement+cose``); a Transparency Service (TS) registers
  it in an append-only, non-equivocating Verifiable Data Structure (VDS) and
  returns a *receipt*; the Issuer bundles receipts into the statement's
  unprotected header (label ``394``) to form a *Transparent Statement*.
* RFC 9942 defines COSE Receipts: signed proofs of VDS properties, conveyed
  in COSE headers. ``395`` = VDS algorithm id (``1`` = RFC9162_SHA256, a
  binary Merkle tree like Certificate Transparency's), ``396`` = the VDP map
  (``-1`` = inclusion proof ``[tree_size, leaf_index, inclusion_path]``,
  ``-2`` = consistency proof).
* Our Rekor anchor is the closest existing analog of a TS: Rekor is a
  Merkle-tree transparency log in the RFC 9162 family, and our anchor record
  pins a feed head at a log index with an integrated timestamp. The spike
  maps that anchor record onto the receipt *shape* — loudly marked as not
  issued by a transparency service.

What this module does NOT do (stated so nobody mistakes the spike for the
standard):

* No binary CBOR/COSE encoding (no CBOR dependency in the repo).
* The "signature" on the statement is Ed25519 over the JCS-canonical JSON
  of the payload — NOT a COSE_Sign1 ``Sig_structure`` signature. A real
  COSE signature needs the CBOR-encoded protected header, which we cannot
  produce byte-identically without a CBOR codec.
* The receipt is never signed by a TS (Rekor does not issue COSE receipts);
  its Merkle inclusion path is empty because the Rekor v1 submit response
  carries no audit path. It is a *shape model*, not a proof.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

#: Our diagnostic envelope marker. NOT part of RFC 9943/9942 — it tells a
#: reader this document is a spike-shaped model, never a conformant message.
SCITT_SPIKE_LABEL = "scitt-spike/1"

#: RFC 9943 §10.1 / §10.2 media type registrations.
SCITT_STATEMENT_MEDIA_TYPE = "application/scitt-statement+cose"
SCITT_RECEIPT_MEDIA_TYPE = "application/scitt-receipt+cose"

# COSE header parameter labels (RFC 9943 §6.1 / RFC 9942 §2).
LABEL_CWT_CLAIMS = 15  # CWT Claims header parameter (RFC 9597 §2)
LABEL_ALG = 1  # COSE alg
LABEL_CONTENT_TYPE = 3  # cty: payload content type
LABEL_KID = 4  # key identifier (RFC 9943 §6: MUST be present w/o x5t/x5chain)
LABEL_RECEIPTS = 394  # unprotected: [+ bstr .cbor Receipt]
LABEL_VDS = 395  # VDS algorithm identifier
LABEL_VDP = 396  # VDP map (proof type -> proofs)

# CWT claim labels inside the CWT Claims header (RFC 8392 / IANA).
CWT_ISS = 1  # issuer: who made the statement
CWT_SUB = 2  # subject: the artifact the statement is about

# COSE algorithms registry.
COSE_ALG_EDDSA = -8  # EdDSA

# VDS registry (RFC 9942 §8.2.2.1): 1 = RFC9162_SHA256 (binary Merkle tree).
VDS_RFC9162_SHA256 = 1
# VDS proof types (RFC 9942 §8.2.2.2).
PROOF_INCLUSION = -1  # [tree_size, leaf_index, inclusion_path]
PROOF_CONSISTENCY = -2  # [tree_size_1, tree_size_2, consistency_path]

#: Statement payload type: our audit anchor statement, named like the
#: DSSE payload type in audit_rekor.py so the two stay recognisable.
STATEMENT_PAYLOAD_TYPE = "application/vnd.northstar.audit-anchor+json"

#: Issuer identity namespace (self-asserted; no PKI behind it — said plainly).
ISSUER_NAMESPACE = "https://northstar-agent-os/keys/"
#: Transparency service identity for receipt-shaped mappings of Rekor anchors.
REKOR_TS_ISSUER = "https://rekor.sigstore.dev"


def _rfc3339_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def build_statement_payload(
    feed: str | Path,
    *,
    exported_at: str | None = None,
) -> dict[str, Any]:
    """The statement *about* the feed: our anchor statement as the payload.

    RFC 9943 §6 leaves the payload format to the issuer; we reuse the exact
    offline anchor manifest (``audit_chain.anchor_manifest``) — feed sha256,
    head chain hash, record count — because it is already the canonical
    "this feed existed in this state" claim. Fails loudly on unchained feeds,
    like the other export shapes.
    """
    from audit_chain import anchor_manifest

    manifest = anchor_manifest(feed)
    head = manifest.get("head_chain_hash")
    if not isinstance(head, str) or not head:
        raise ValueError(
            "audit feed has no chained head to export (is it a chained feed?)"
        )
    return {
        "anchor": manifest["anchor"],
        "chain": manifest["chain"],
        "feed_sha256": manifest["feed_sha256"],
        "head_chain_hash": head,
        "records": manifest["records"],
        "exported_at": exported_at or _rfc3339_now(),
    }


def build_signed_statement(
    feed: str | Path,
    *,
    key_id: str,
    seed: bytes | None = None,
    issuer: str | None = None,
    exported_at: str | None = None,
) -> dict[str, Any]:
    """A SCITT Signed Statement *shape* for the feed.

    Protected header follows RFC 9943 §6.1 CDDL with integer labels:
    ``15`` (CWT claims ``{1: iss, 2: sub}``), ``1`` (alg ``-8`` EdDSA),
    ``3`` (cty = our anchor statement type), ``4`` (kid — required by §6
    when no x5t/x5chain is present, which is our case: raw Ed25519 keys).

    ``iss`` identifies the issuer (our key namespace + key id); ``sub``
    identifies the artifact the statement is about (the feed, by sha256).
    """
    if not isinstance(key_id, str) or not key_id:
        raise ValueError("key_id is required: the issuer identity binds the statement")
    payload = build_statement_payload(feed, exported_at=exported_at)
    iss = issuer or f"{ISSUER_NAMESPACE}{key_id}"
    sub = f"audit-feed/sha256:{payload['feed_sha256']}"
    protected: dict[Any, Any] = {
        LABEL_CWT_CLAIMS: {CWT_ISS: iss, CWT_SUB: sub},
        LABEL_ALG: COSE_ALG_EDDSA,
        LABEL_CONTENT_TYPE: STATEMENT_PAYLOAD_TYPE,
        LABEL_KID: key_id,
    }
    statement: dict[str, Any] = {
        "protected": protected,
        "unprotected": {},  # receipts land under label 394 via add_receipts()
        "payload": payload,  # inlined: JSON-diagnostic form (real COSE may detach)
        "signature": None,
    }
    if seed is not None:
        statement["signature"] = _sign_payload_json(payload, seed=seed, key_id=key_id)
    return statement


def _sign_payload_json(
    payload: dict[str, Any], *, seed: bytes, key_id: str
) -> dict[str, Any]:
    """Ed25519 over the JCS-canonical JSON of the payload.

    This is NOT a COSE_Sign1 signature (which signs the CBOR-encoded
    ``Sig_structure``). It is recorded honestly as a JSON-level signature so
    the spike can still demonstrate issuer binding without a CBOR codec.
    """
    from audit_chain import jcs_canonical_json
    from ed25519 import public_key as ed_public_key
    from ed25519 import sign as ed_sign

    if len(seed) != 32:
        raise ValueError("the Ed25519 seed must be 32 bytes")
    canonical = jcs_canonical_json(payload)
    signature = ed_sign(seed, canonical)
    return {
        "alg": COSE_ALG_EDDSA,
        "kid": key_id,
        "sig": signature.hex(),
        "pubkey": ed_public_key(seed).hex(),
        "signed_over": "jcs-canonical-json(statement.payload)",
        "payload_sha256": hashlib.sha256(canonical).hexdigest(),
        "note": (
            "Ed25519 over canonical JSON; NOT a COSE_Sign1 Sig_structure "
            "signature — binary CBOR/Cose encoding is out of scope for this spike."
        ),
    }


def verify_statement_signature(statement: dict[str, Any]) -> tuple[bool, str]:
    """Verify the JSON-level signature on a signed statement shape.

    Returns ``(ok, note)``; never raises on malformed input.
    """
    try:
        signature = statement.get("signature")
        if not isinstance(signature, dict):
            return False, "statement is unsigned"
        payload = statement["payload"]
        from audit_chain import jcs_canonical_json
        from ed25519 import verify as ed_verify

        canonical = jcs_canonical_json(payload)
        if hashlib.sha256(canonical).hexdigest() != signature.get("payload_sha256"):
            return False, "statement payload changed after signing"
        pubkey = bytes.fromhex(signature["pubkey"])
        if not ed_verify(pubkey, canonical, bytes.fromhex(signature["sig"])):
            return False, "statement signature invalid (not made by the claimed key)"
        return True, "statement JSON-level signature ok"
    except (KeyError, TypeError, ValueError) as error:
        return False, f"malformed signed statement: {error}"


def anchor_record_to_receipt(anchor: dict[str, Any]) -> dict[str, Any]:
    """Map our Rekor anchor record onto the COSE Receipt *shape* (RFC 9942 §4).

    The receipt claims, in RFC terms: protected ``{1: -8, 15: {1: iss, 2: sub},
    395: 1}`` — EdDSA, issued by the transparency service (Rekor), VDS =
    RFC9162_SHA256 (Rekor is a Merkle-tree log in that family) — and
    unprotected ``{396: {-1: [[tree_size, leaf_index, inclusion_path]]}}`` —
    an inclusion proof for the anchored entry.

    Honest limits, stated on the record itself (``receipt_status``):

    * ``"shape-only"`` — Rekor does not issue COSE receipts; this receipt is
      self-modelled from our anchor record, never signed by a TS. The
      ``signature`` field is therefore ``None``: a real receipt MUST be a
      signed COSE_Sign1 (RFC 9942 §4.3).
    * ``"proof": "incomplete"`` — the inclusion path is empty because the
      Rekor v1 submit response carries no Merkle audit path. ``tree_size``
      is ``log_index + 1`` (the tree held at least that many entries when
      ours was integrated); the real path must come from the log.
    """
    try:
        log_index = int(anchor["log_index"])
        uuid = str(anchor["uuid"])
        payload = anchor["payload"]
        head = payload["head_chain_hash"]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"not a northstar rekor anchor record: {error}") from None
    if anchor.get("anchor") != "northstar-rekor-anchor/1":
        raise ValueError("not a northstar rekor anchor record (bad 'anchor' marker)")
    receipt = {
        "protected": {
            LABEL_ALG: COSE_ALG_EDDSA,
            LABEL_CWT_CLAIMS: {
                CWT_ISS: REKOR_TS_ISSUER,
                CWT_SUB: f"rekor-entry:{uuid}",
            },
            LABEL_VDS: VDS_RFC9162_SHA256,
        },
        "unprotected": {
            LABEL_VDP: {
                PROOF_INCLUSION: [
                    # [tree_size, leaf_index, inclusion_path]
                    [log_index + 1, log_index, []],
                ]
            }
        },
        "payload": None,  # detached, as RFC 9942 profiles recommend
        "signature": None,  # shape-only: no TS signature exists
        "media_type": SCITT_RECEIPT_MEDIA_TYPE,
        "receipt_status": "shape-only",
        "proof": "incomplete",
        "source_anchor": {
            "uuid": uuid,
            "log_index": log_index,
            "integrated_time": anchor.get("integrated_time"),
            "payload_sha256": anchor.get("payload_sha256"),
            "anchored_head": head,
        },
        "mapping_notes": [
            "vds=1 (RFC9162_SHA256): Rekor is a Merkle-tree transparency log "
            "in the RFC 9162 family; the mapping is by construction, not by "
            "a registry claim from the log.",
            "tree_size=log_index+1: the log held at least this many entries "
            "at integration time; the true tree size at that moment is not "
            "returned by the v1 submit call.",
            "inclusion_path=[]: the v1 submit response carries no Merkle "
            "audit path — a conformant receipt needs the path from the log.",
            "signature=None: a real receipt is a COSE_Sign1 signed by the TS "
            "(RFC 9942 §4.3); Rekor issues no COSE receipts, so this shape "
            "cannot carry one.",
        ],
    }
    return receipt


def add_receipts(statement: dict[str, Any], receipts: list[dict[str, Any]]) -> dict[str, Any]:
    """Form the Transparent Statement: receipts under unprotected label 394.

    RFC 9943 §7: a Transparent Statement is a Signed Statement whose
    unprotected header carries one or more receipts (label ``394``), each a
    ``bstr .cbor Receipt`` — here, JSON-diagnostic receipt shapes.
    """
    if not receipts:
        raise ValueError("a transparent statement needs at least one receipt")
    statement = dict(statement)
    unprotected = dict(statement.get("unprotected") or {})
    existing = list(unprotected.get(LABEL_RECEIPTS) or [])
    existing.extend(receipts)
    unprotected[LABEL_RECEIPTS] = existing
    statement["unprotected"] = unprotected
    return statement


def build_scitt_bundle(
    feed: str | Path,
    *,
    key_id: str,
    seed: bytes | None = None,
    issuer: str | None = None,
    rekor_anchor: dict[str, Any] | None = None,
    exported_at: str | None = None,
) -> dict[str, Any]:
    """The full spike bundle: signed statement, optionally transparent.

    Without ``rekor_anchor`` the bundle is a lone Signed Statement
    (``application/scitt-statement+cose`` shape). With one, the anchor is
    mapped to a receipt shape and embedded under unprotected label ``394``,
    forming the Transparent Statement shape
    (``application/scitt-receipt+cose`` receipt inside).
    """
    statement = build_signed_statement(
        feed, key_id=key_id, seed=seed, issuer=issuer, exported_at=exported_at
    )
    receipts: list[dict[str, Any]] = []
    if rekor_anchor is not None:
        receipts.append(anchor_record_to_receipt(rekor_anchor))
        statement = add_receipts(statement, receipts)
    bundle = {
        "scitt": SCITT_SPIKE_LABEL,
        "media_type": (
            SCITT_RECEIPT_MEDIA_TYPE if receipts else SCITT_STATEMENT_MEDIA_TYPE
        ),
        "encoding": "json-diagnostic",
        "encoding_note": (
            "JSON diagnostic model of the RFC 9943 §6.1 / RFC 9942 §4 CDDL; "
            "NOT binary COSE/CBOR. Integer labels are the exact registry values "
            "in the in-memory model; the JSON encoding renders them as decimal "
            "string object keys (JSON/JCS cannot carry integer keys)."
        ),
        "statement": statement,
        "mapping_notes": [
            "protected/15 {1: iss, 2: sub}: iss = our key namespace + key_id "
            "(self-asserted issuer identity, no PKI); sub = the feed by "
            "sha256 (the artifact the statement is about).",
            "protected/1 = -8 (EdDSA): matches our Ed25519 feed/anchor keys.",
            "protected/3 (cty) = application/vnd.northstar.audit-anchor+json: "
            "the anchor statement payload type, named like the DSSE type in "
            "audit_rekor.py.",
            "protected/4 (kid): present because no x5t/x5chain — RFC 9943 §6 "
            "requires kid in exactly this case.",
            "statement signature: Ed25519 over JCS-canonical JSON of the "
            "payload — JSON-level only, not a COSE_Sign1 Sig_structure.",
            "receipt (when present): shape-only model of our Rekor anchor; "
            "see receipt.mapping_notes for the four honest limits.",
        ],
    }
    return bundle


def _stringify_int_keys(obj: Any) -> Any:
    """Recursively render integer COSE labels as decimal JSON object keys.

    RFC 8785 (JCS) only allows string object keys, so the JSON-diagnostic
    encoding cannot carry the integer labels natively; the in-memory model
    keeps the exact integers (what the tests pin) and only the *encoding*
    renders them as strings. Documented in the bundle's ``encoding_note``.
    """
    if isinstance(obj, dict):
        return {
            (str(key) if isinstance(key, int) else key): _stringify_int_keys(value)
            for key, value in obj.items()
        }
    if isinstance(obj, list):
        return [_stringify_int_keys(item) for item in obj]
    return obj


def bundle_to_json_bytes(bundle: dict[str, Any]) -> bytes:
    """JCS-canonical JSON bytes of the bundle (deterministic).

    Integer COSE labels render as decimal string object keys in the encoding
    (JSON cannot carry integer keys); the in-memory bundle keeps the integers.
    """
    from audit_chain import jcs_canonical_json

    return jcs_canonical_json(_stringify_int_keys(bundle))
