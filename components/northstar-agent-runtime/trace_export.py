"""Export a Northstar audit chain head as a TRACE v0.2-shaped Trust Record.

TRACE (Trust, Runtime Attestation, and Compliance Evidence) is the Linux
Foundation-hosted open specification (v0.2, Draft/RFC, pre-ratification)
for portable governance evidence about an AI agent execution. The
specification itself reserves the slot this module fills: a Trust Record
"commits the audit chain by hash" (§3.3.2), and a record assembled from an
audit trail is the honest ``origin.kind = "log-import"`` shape (§3.1.1),
which MUST carry ``runtime.platform = "software-only"``.

What this module emits is a **TRACE v0.2-shaped evidence record
(software-only / log-import)** — NOT a conformance claim:

* TRACE v0.2 is a Developer Preview: fields, wire formats and conformance
  requirements may change before v1.0. Nothing here claims "TRACE
  conformant"; schema validity alone never establishes conformance, and
  semantic/verification checks are the verifier's job.
* A software-only log-import record is *environment evidence about an
  unattested execution*: it "does not launder assurance" (§3.1.1). It must
  never be presented as hardware-attested evidence.
* Fields Northstar cannot honestly fill (model identity, SLSA build
  provenance, SCITT transparency receipt) are **omitted**, never
  fabricated. The record points at the audit feed instead
  (``references[].rel = "behavior-trace"``), so a verifier can resolve the
  underlying evidence.

Field mapping (all offline, pure software, off the hot path):

* ``tool_transcript.hash`` = ``"sha256:" + <audit chain head hash>`` —
  the Trust Record commits the chain by hash; receipts live in the chain,
  not in the record (§3.3.2).
* ``tool_transcript.call_count`` = number of ``tool_result`` records in
  the feed (the audit feed's tool-call records).
* ``references`` gains ``{rel: "behavior-trace", id, resolver, digest}``
  pointing at the feed file (whole-file sha256), so the behaviour record
  the Trust Record is "the environment evidence" for stays resolvable.
* ``policy.enforcement_mode = "enforce"`` — Northstar really does run a
  policy gate; ``bundle_hash`` is included only when the operator passes
  one (``--policy-bundle-hash``).
* ``origin = {kind: "log-import", producer: "northstar-audit-export", ...}``
  with ``runtime.platform = "software-only"`` (a MUST for non-``self``
  origins, §3.1.1).
* ``eat_profile = "tag:agentrust-io.com,2026:trace-v0.2"``.
* Optional embedded Ed25519 signature (``--seed-hex``): base64url
  (no padding) over the RFC 8785 (JCS) canonical form of the record with
  the ``signature`` field absent — the §3.2.2 embedded profile — plus
  ``cnf.jwk`` carrying the verifying key. Unsigned records carry no
  ``signature``/``cnf`` at all; the CLI says so on stderr.

Canonicalization reuses Northstar's hand-written RFC 8785 implementation
(``audit_chain.jcs_canonical_json``), cross-validated against the TRACE
spec's own JCS conformance vectors (see ``tests/test_trace_export.py``:
the supplementary-plane key-order fixture from
``examples/delegation-link/24-parent-key-supplementary-plane.json``).

Design note for the next step (not implemented here): once the emitted
Trust Record is anchored in an append-only transparency log (e.g. the
existing Sigstore Rekor flow in ``audit_rekor`` pointed at the record
instead of the feed head), the log's inclusion proof URI fills the
``transparency`` field. See ``docs/concepts/trace-export.md``.
"""
from __future__ import annotations

import base64
import hashlib
import time
from pathlib import Path
from typing import Any

#: EAT profile claim identifying a TRACE v0.2 record. A v0.2 verifier MUST
#: reject the v0.1 identifier; there is no coexistence (spec, "Changes from
#: v0.1").
TRACE_EAT_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"

#: Honesty marker for every human-facing description of this export.
TRACE_SHAPE_LABEL = "TRACE v0.2-shaped evidence record (software-only/log-import)"

#: TRACE v0.2 is a pre-ratification draft (Developer Preview): fields and
#: conformance requirements may change before v1.0.
TRACE_SPEC_STATUS = "v0.2 Draft/RFC pre-ratification (Developer Preview)"

#: Producer identifier used in ``origin`` and as the ``behavior-trace``
#: reference resolver.
PRODUCER = "northstar-audit-export"

#: Data-class lattice from the TRACE delegation profile fixtures
#: (public < internal < confidential < restricted).
DATA_CLASSES = ("public", "internal", "confidential", "restricted")


def _b64url_no_pad(raw: bytes) -> str:
    """Canonical base64url encoding (RFC 4648 §5), no padding — §3.2.2."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _software_only_measurement() -> str:
    """Recomputable stand-in for ``runtime.measurement`` on software-only.

    There is no measured boot chain to commit to, so the measurement
    commits to the exporter's identity instead: anyone can recompute it,
    and it makes no hardware claim.
    """
    from audit_chain import jcs_canonical_json

    identity = {
        "producer": PRODUCER,
        "component": "northstar-agent-runtime",
        "platform": "software-only",
    }
    return "sha256:" + hashlib.sha256(jcs_canonical_json(identity)).hexdigest()


def _feed_session_ids(first_record: dict[str, Any]) -> tuple[str | None, str | None]:
    """(session_id, run_id) from the feed's genesis anchor, if present."""
    from audit_chain import feed_genesis_ids

    session_id, run_id, _started_ts = feed_genesis_ids(first_record)
    return session_id, run_id


def build_trace_record(
    feed: str | Path,
    *,
    policy_bundle_hash: str | None = None,
    data_class: str | None = None,
    subject: str | None = None,
    model_provider: str | None = None,
    model_id: str | None = None,
    seed: bytes | None = None,
    iat: int | None = None,
) -> dict[str, Any]:
    """Build a TRACE v0.2-shaped Trust Record for one audit feed file.

    The feed must be a *chained* audit feed (``northstar audit verify``
    would report OK): the record commits the chain head by hash, and an
    unchained feed has no head to commit. Raises ``ValueError`` with a
    plain message when the feed is unprotected, broken, or unreadable.

    ``seed`` is an optional 32-byte Ed25519 seed; when given, the record
    is signed (embedded profile, §3.2.2) and carries ``cnf.jwk``.
    Unsigned records carry neither ``signature`` nor ``cnf``.
    """
    from audit_chain import anchor_manifest, verify_file

    path = Path(feed)
    try:
        result = verify_file(path)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"cannot read audit feed {path}: {error}") from error
    if result.unprotected:
        raise ValueError(
            f"audit feed {path} is UNPROTECTED (no hash chain): "
            "--trace needs a chained feed, export with --chain first"
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

    # Genesis names the session/run this feed claims to describe.
    session_id: str | None = None
    run_id: str | None = None
    call_count = 0
    try:
        raw = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError(f"cannot read audit feed {path}: {error}") from error
    import json as _json

    first = True
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        record = _json.loads(line)
        if first:
            session_id, run_id = _feed_session_ids(record)
            first = False
        if record.get("event") == "tool_result":
            call_count += 1

    subject_value = subject or (
        f"did:northstar:run/{run_id}"
        if run_id
        else (f"did:northstar:session/{session_id}" if session_id else "did:northstar:unknown")
    )
    source_event_id = run_id or session_id or path.name

    policy: dict[str, Any] = {"enforcement_mode": "enforce"}
    if policy_bundle_hash is not None:
        if not isinstance(policy_bundle_hash, str) or not policy_bundle_hash.startswith("sha256:"):
            raise ValueError("--policy-bundle-hash must look like 'sha256:<hex>'")
        policy["bundle_hash"] = policy_bundle_hash

    record: dict[str, Any] = {
        "eat_profile": TRACE_EAT_PROFILE,
        "iat": int(time.time()) if iat is None else iat,
        "subject": subject_value,
        "runtime": {
            "platform": "software-only",
            "measurement": _software_only_measurement(),
        },
        "policy": policy,
        "tool_transcript": {
            "hash": "sha256:" + head,
            "call_count": call_count,
        },
        "origin": {
            "kind": "log-import",
            "producer": PRODUCER,
            "source_event_id": source_event_id,
            "ingested_at": int(time.time()) if iat is None else iat,
        },
        "references": [
            {
                "rel": "behavior-trace",
                "id": source_event_id,
                "resolver": PRODUCER,
                "digest": "sha256:" + feed_sha256,
            }
        ],
    }
    if data_class is not None:
        if data_class not in DATA_CLASSES:
            raise ValueError(f"--data-class must be one of {', '.join(DATA_CLASSES)}")
        record["data_class"] = data_class
    if model_provider is not None or model_id is not None:
        model: dict[str, Any] = {}
        if model_provider is not None:
            model["provider"] = model_provider
        if model_id is not None:
            model["model_id"] = model_id
        record["model"] = model

    if seed is not None:
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        from audit_chain import jcs_canonical_json
        from ed25519 import public_key, sign

        pubkey = public_key(seed)
        record["cnf"] = {
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": _b64url_no_pad(pubkey),
            }
        }
        # Embedded profile (§3.2.2): signature over the canonical form
        # with the signature field absent; cnf (incl. cnf.jwk) IS covered.
        # Canonical base64url, no padding.
        body = {key: value for key, value in record.items() if key != "signature"}
        signature = sign(seed, jcs_canonical_json(body))
        record["signature"] = _b64url_no_pad(signature)
    return record


def record_to_json_bytes(record: dict[str, Any]) -> bytes:
    """JCS canonical bytes of the Trust Record (the digest/signing form)."""
    from audit_chain import jcs_canonical_json

    return jcs_canonical_json(record)


def verify_trace_signature(record: dict[str, Any], public_key: bytes) -> bool:
    """Check an embedded Ed25519 signature on an exported Trust Record.

    False when the record carries no signature. The preimage is the JCS
    canonical form with the ``signature`` field absent (§3.2.2).
    """
    from audit_chain import jcs_canonical_json
    from ed25519 import verify

    signature = record.get("signature")
    if not isinstance(signature, str) or not signature:
        return False
    try:
        padding = "=" * (-len(signature) % 4)
        sig_bytes = base64.urlsafe_b64decode(signature + padding)
    except (ValueError, base64.binascii.Error):
        return False
    body = {key: value for key, value in record.items() if key != "signature"}
    return verify(public_key, jcs_canonical_json(body), sig_bytes)
