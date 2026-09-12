"""Portable, signed envelope for offline evidence verification.

This module composes existing evidence primitives without changing their v1
schemas.  It is deliberately an envelope, not an authorization token:
``signer`` is an identity claim and must not be treated as permission.

The injected SignatureScheme interface can host a public-key implementation,
but this repository ships only HMACSignatureScheme from the standard library.
HMAC is explicitly same-key verification; it is not third-party independent
verification.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from evidence_bundle import EvidenceError
from evidence_chain import ChainError, EvidenceCheckpoint
from evidence_disclosure import Disclosure, DisclosureError, make_disclosure, verify_disclosure
from evidence_proof import ProofAttestation, ProofError, make_proof_attestation, verify_route_evidence_proof
from key_lifecycle import KeyLifecycleError, KeyRecord, KeyHistory, ZERO as KEY_ZERO, _record_digest

SCHEMA = "northstar.evidence-notarization.v1"
_SIGNER_KINDS = frozenset({"host", "session", "agent"})
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
_FIELDS = frozenset({
    "schema_version", "subject", "disclosure", "attestation", "key_history",
    "checkpoint_head", "signer", "key_id", "signature",
})


class NotarizationError(ValueError):
    """Malformed, unverified, or cryptographically inconsistent envelope."""


class SignatureScheme(Protocol):
    mode: str

    def sign(self, payload: bytes, *, key_id: str) -> str:
        ...

    def verify(self, payload: bytes, signature: str, *, key_id: str) -> bool:
        ...


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NotarizationError("envelope value is not canonical JSON") from exc


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise NotarizationError(f"{field} is not a sha256 digest")
    return value


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise NotarizationError(f"{field} is invalid")
    return value


def _copy_json(value: Any, field: str) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise NotarizationError(f"{field} is not JSON data") from exc


def _attestation(value: Any) -> ProofAttestation:
    fields = {
        "schema_version", "verdict", "route_id", "proof_digest", "lineage_digest",
        "bundle_root", "checkpoint_root",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise NotarizationError("attestation fields are invalid")
    if value["schema_version"] != "northstar.proof-attestation.v1" or value["verdict"] != "verified":
        raise NotarizationError("attestation is not a verified v1 attestation")
    route_id = _id(value["route_id"], "attestation route_id")
    return ProofAttestation(
        value["schema_version"], value["verdict"], route_id,
        _digest(value["proof_digest"], "attestation proof_digest"),
        _digest(value["lineage_digest"], "attestation lineage_digest"),
        _digest(value["bundle_root"], "attestation bundle_root"),
        _digest(value["checkpoint_root"], "attestation checkpoint_root"),
    )


def _signer(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"kind", "id"}:
        raise NotarizationError("signer declaration is invalid")
    if value["kind"] not in _SIGNER_KINDS:
        raise NotarizationError("signer kind is invalid")
    return {"kind": _id(value["kind"], "signer kind"), "id": _id(value["id"], "signer id")}


@dataclass(frozen=True)
class EvidenceEnvelope:
    schema_version: str
    subject: dict[str, Any]
    disclosure: dict[str, Any]
    attestation: dict[str, Any]
    key_history: tuple[dict[str, Any], ...]
    checkpoint_head: dict[str, Any]
    signer: dict[str, str]
    key_id: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "subject": self.subject,
            "disclosure": self.disclosure,
            "attestation": self.attestation,
            "key_history": list(self.key_history),
            "checkpoint_head": self.checkpoint_head,
            "signer": self.signer,
            "key_id": self.key_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: Any) -> "EvidenceEnvelope":
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise NotarizationError("envelope fields are invalid")
        if value["schema_version"] != SCHEMA:
            raise NotarizationError("envelope schema is invalid")
        subject = _copy_json(value["subject"], "subject")
        if not isinstance(subject, dict):
            raise NotarizationError("subject must be an object")
        disclosure = _copy_json(value["disclosure"], "disclosure")
        if not isinstance(disclosure, dict):
            raise NotarizationError("disclosure must be an object")
        attestation = _copy_json(value["attestation"], "attestation")
        checkpoint = _copy_json(value["checkpoint_head"], "checkpoint_head")
        if not isinstance(attestation, dict) or not isinstance(checkpoint, dict):
            raise NotarizationError("attestation and checkpoint must be objects")
        history = value["key_history"]
        if not isinstance(history, list) or not history:
            raise NotarizationError("key history must be a non-empty list")
        copied_history = tuple(_copy_json(item, "key history") for item in history)
        if not all(isinstance(item, dict) for item in copied_history):
            raise NotarizationError("key history records must be objects")
        key_id = _id(value["key_id"], "key_id")
        signature = value["signature"]
        if not isinstance(signature, str) or _SIGNATURE.fullmatch(signature) is None:
            raise NotarizationError("envelope signature is invalid")
        return cls(
            SCHEMA, subject, disclosure, attestation, copied_history, checkpoint,
            _signer(value["signer"]), key_id, signature,
        )


class HMACSignatureScheme:
    """Same-key compatibility scheme; not independent third-party verification."""

    mode = "same-key"

    def __init__(self, secrets: Mapping[str, bytes]):
        if not isinstance(secrets, Mapping):
            raise NotarizationError("HMAC secret map is invalid")
        self._secrets: dict[str, bytes] = {}
        for key_id, secret in secrets.items():
            key = _id(key_id, "key_id")
            if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
                raise NotarizationError("HMAC secret is too short")
            self._secrets[key] = bytes(secret)

    def _secret(self, key_id: str) -> bytes:
        try:
            return self._secrets[key_id]
        except KeyError as exc:
            raise NotarizationError("HMAC key is unavailable") from exc

    def sign(self, payload: bytes, *, key_id: str) -> str:
        value = hmac.new(self._secret(_id(key_id, "key_id")), payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    def verify(self, payload: bytes, signature: str, *, key_id: str) -> bool:
        expected = self.sign(payload, key_id=key_id)
        return hmac.compare_digest(expected, signature)


def _checkpoint(value: Any) -> EvidenceCheckpoint:
    try:
        return EvidenceCheckpoint.from_dict(value)
    except (ChainError, TypeError, KeyError) as exc:
        raise NotarizationError('checkpoint head is invalid') from exc


def _history_records(history: KeyHistory) -> tuple[dict[str, Any], ...]:
    records = getattr(history, 'records', ())
    if not records:
        raise NotarizationError('key history is empty')
    return tuple(record.to_dict() for record in records)


def _history_state(records: tuple[dict[str, Any], ...], *, anchor: str | None,
                   key_id: str) -> tuple[str, tuple[str, ...]]:
    parsed: list[KeyRecord] = []
    previous = KEY_ZERO
    expected_revision = 1
    for raw in records:
        try:
            record = KeyRecord.from_dict(raw)
        except KeyLifecycleError as exc:
            raise NotarizationError('embedded key history is malformed') from exc
        if record.revision != expected_revision or record.previous_digest != previous:
            raise NotarizationError('embedded key history chain is broken')
        if _record_digest(record.revision, record.key_id, record.material_digest,
                          record.action, record.previous_digest) != record.record_digest:
            raise NotarizationError('embedded key history digest mismatch')
        parsed.append(record)
        previous = record.record_digest
        expected_revision += 1
    if anchor is None:
        anchor_reasons = ('anchor_unpinned',)
    else:
        _digest(anchor, 'key history anchor')
        if parsed[0].record_digest != anchor:
            raise NotarizationError('key history anchor mismatch')
        anchor_reasons = ()
    matching = [record for record in parsed if record.key_id == key_id]
    if not matching:
        raise NotarizationError('envelope key is absent from key history')
    last = matching[-1]
    if last.action == 'revoked':
        raise NotarizationError('envelope key is revoked')
    if last.action == 'rotated':
        state = 'trusted'
    else:
        state = 'trusted-retired' if any(
            record.revision > last.revision and record.action == 'rotated'
            for record in parsed
        ) else 'trusted'
    return state, anchor_reasons


def _scheme_call(scheme: SignatureScheme, method: str, *args: Any, **kwargs: Any) -> Any:
    if not hasattr(scheme, method) or not callable(getattr(scheme, method)):
        raise NotarizationError('signature scheme is incomplete')
    try:
        return getattr(scheme, method)(*args, **kwargs)
    except NotarizationError:
        raise
    except Exception as exc:
        raise NotarizationError('signature scheme failed') from exc


def build_envelope(route_record: Any, lineage: Any, bundle: Any,
                   checkpoint_chain: Any, event: Any, proof: Any, handoff: Any,
                   *, index: int, key_id: str, history: KeyHistory,
                   signer: dict[str, str], scheme: SignatureScheme) -> EvidenceEnvelope:
    if not isinstance(history, KeyHistory):
        raise NotarizationError('key history is invalid')
    signer_value = _signer(signer)
    key_value = _id(key_id, 'key_id')
    state = history.verdict(key_value).state
    if state not in {'trusted', 'trusted-retired'}:
        raise NotarizationError('signing key is not trusted')
    try:
        result = verify_route_evidence_proof(
            route_record, lineage, bundle, checkpoint_chain, event, proof, handoff
        )
    except Exception as exc:
        raise NotarizationError('evidence verification failed') from exc
    if result.verdict != 'verified':
        raise NotarizationError('cannot notarize unverified evidence')
    try:
        disclosure = make_disclosure(bundle, index)
        checkpoints = list(checkpoint_chain.read())
    except (EvidenceError, ChainError, ValueError, TypeError) as exc:
        raise NotarizationError('evidence disclosure or checkpoint failed') from exc
    if not checkpoints:
        raise NotarizationError('checkpoint head is missing')
    attestation = make_proof_attestation(
        route_record, lineage, bundle, checkpoint_chain, event, proof, handoff
    )
    envelope = EvidenceEnvelope(
        SCHEMA,
        _copy_json(event.to_dict() if hasattr(event, 'to_dict') else event, 'subject'),
        disclosure.to_dict(),
        attestation.to_dict(),
        _history_records(history),
        checkpoints[-1].to_dict(),
        signer_value,
        key_value,
        '',
    )
    signature = _scheme_call(scheme, 'sign', _canonical(envelope.unsigned_dict()), key_id=key_value)
    if not isinstance(signature, str) or _SIGNATURE.fullmatch(signature) is None:
        raise NotarizationError('signature scheme returned an invalid signature')
    return EvidenceEnvelope(**{**envelope.__dict__, 'signature': signature})


def verify_envelope(envelope: EvidenceEnvelope, *, anchor: str | None,
                    scheme: SignatureScheme, expected_root: str | None = None) -> EnvelopeVerdict:
    if not isinstance(envelope, EvidenceEnvelope):
        raise NotarizationError('envelope is invalid')
    try:
        parsed = EvidenceEnvelope.from_dict(envelope.to_dict())
        attestation = _attestation(parsed.attestation)
        disclosure = Disclosure.from_dict(parsed.disclosure)
        checkpoint = _checkpoint(parsed.checkpoint_head)
    except (NotarizationError, DisclosureError) as exc:
        raise NotarizationError('envelope structure is invalid') from exc
    if not _scheme_call(
        scheme, 'verify', _canonical(parsed.unsigned_dict()), parsed.signature,
        key_id=parsed.key_id,
    ):
        raise NotarizationError('envelope signature mismatch')
    _, anchor_reasons = _history_state(
        parsed.key_history, anchor=anchor, key_id=parsed.key_id
    )
    root = disclosure.root_digest
    if attestation.bundle_root != root or attestation.checkpoint_root != checkpoint.current_root:
        raise NotarizationError('attestation roots do not match envelope evidence')
    if checkpoint.current_root != root:
        raise NotarizationError('checkpoint root does not match disclosure root')
    if expected_root is not None and expected_root != root:
        raise NotarizationError('disclosure root does not match expected root')
    try:
        disclosure_verdict = verify_disclosure(
            disclosure, subject=parsed.subject, expected_root=expected_root
        )
    except (EvidenceError, DisclosureError, ValueError) as exc:
        raise NotarizationError('subject is not included by disclosure') from exc
    if disclosure_verdict.state == 'verified-unpinned' and expected_root is not None:
        raise NotarizationError('pinned disclosure did not verify')
    unverified = list(disclosure_verdict.reasons)
    unverified.extend(disclosure_verdict.unverified)
    unverified.extend(anchor_reasons)
    mode = getattr(scheme, 'mode', 'injected-scheme')
    if mode == 'same-key':
        unverified.append('same-key')
    critical_unpinned = {'root_unpinned', 'anchor_unpinned'}
    state = 'verified-unpinned' if critical_unpinned.intersection(unverified) else 'verified'
    return EnvelopeVerdict(state, (), tuple(dict.fromkeys(unverified)))


@dataclass(frozen=True)
class EnvelopeVerdict:
    state: str
    reasons: tuple[str, ...] = ()
    unverified: tuple[str, ...] = ()


__all__ = [
    'SCHEMA', 'EnvelopeVerdict', 'EvidenceEnvelope', 'HMACSignatureScheme',
    'NotarizationError', 'SignatureScheme', 'build_envelope', 'verify_envelope',
]
