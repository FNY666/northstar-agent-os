"""Challenge-bound sealing for proof attestations, so a valid seal cannot be replayed.

A signature proves who said it. It does not prove the verifier asked for it now.
This module binds an attestation to a single-use, expiring challenge, so a seal
captured from an earlier exchange is refused rather than accepted again.
"""
from __future__ import annotations
import base64, hashlib, hmac, json, os, re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from evidence_proof import ProofAttestation
from proof_signing import ProofSignatureError

SCHEMA = 'northstar.sealed-attestation.v1'
DOMAIN = b'northstar.attestation-freshness.v1'
_ID_RE = re.compile(r'^[A-Za-z0-9._:-]{1,64}$')
_CHALLENGE_RE = re.compile(r'^[0-9a-f]{32}$')
_DIGEST_RE = re.compile(r'^sha256:[0-9a-f]{64}$')
_SIGNATURE_RE = re.compile(r'^[A-Za-z0-9_-]{16,256}$')


class FreshnessError(ProofSignatureError):
    """A seal that is stale, replayed, or not bound to the expected challenge."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def _sha(data: bytes) -> str:
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def _validate_secret(secret: bytes) -> bytes:
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
        raise FreshnessError('signing secret is too short')
    return bytes(secret)


def _signing_domain(challenge_id: str, attestation_digest: str, key_id: str) -> bytes:
    return b'\x00'.join([DOMAIN, challenge_id.encode(), attestation_digest.encode(), key_id.encode()])


def _seal(secret: bytes, challenge_id: str, attestation_digest: str, key_id: str) -> str:
    raw = hmac.new(bytes(secret), _signing_domain(challenge_id, attestation_digest, key_id), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def _attestation_digest(attestation: ProofAttestation) -> str:
    if not isinstance(attestation, ProofAttestation) or attestation.verdict != 'verified':
        raise FreshnessError('only a verified attestation can be sealed')
    return _sha(_canonical(attestation.to_dict()))


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    issued_at: int
    expires_at: int

    def to_dict(self) -> dict[str, Any]:
        return {'challenge_id': self.challenge_id, 'issued_at': self.issued_at, 'expires_at': self.expires_at}


@dataclass(frozen=True)
class SealedAttestation:
    schema_version: str
    challenge_id: str
    key_id: str
    attestation_digest: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            'schema_version': self.schema_version,
            'challenge_id': self.challenge_id,
            'key_id': self.key_id,
            'attestation_digest': self.attestation_digest,
            'signature': self.signature,
        }

    @classmethod
    def from_dict(cls, value: Any) -> 'SealedAttestation':
        if not isinstance(value, dict) or set(value) != {
            'schema_version', 'challenge_id', 'key_id', 'attestation_digest', 'signature'
        }:
            raise FreshnessError('sealed attestation fields invalid')
        if value['schema_version'] != SCHEMA:
            raise FreshnessError('sealed attestation schema invalid')
        if not isinstance(value['challenge_id'], str) or _CHALLENGE_RE.fullmatch(value['challenge_id']) is None:
            raise FreshnessError('sealed attestation challenge invalid')
        if not isinstance(value['key_id'], str) or _ID_RE.fullmatch(value['key_id']) is None:
            raise FreshnessError('sealed attestation key id invalid')
        if not isinstance(value['attestation_digest'], str) or _DIGEST_RE.fullmatch(value['attestation_digest']) is None:
            raise FreshnessError('sealed attestation digest invalid')
        if not isinstance(value['signature'], str) or _SIGNATURE_RE.fullmatch(value['signature']) is None:
            raise FreshnessError('sealed attestation signature invalid')
        return cls(
            value['schema_version'],
            value['challenge_id'],
            value['key_id'],
            value['attestation_digest'],
            value['signature'],
        )


class ChallengeBook:
    """Issues single-use expiring challenges and refuses anything else.

    The clock is injected, never read from the host: the caller owns time.
    """

    def __init__(self, *, clock: Callable[[], int], ttl: int = 300, nonce_source: Callable[[int], bytes] | None = None):
        if not callable(clock):
            raise FreshnessError('clock must be callable')
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 1:
            raise FreshnessError('ttl must be a positive integer')
        self._clock = clock
        self._ttl = ttl
        self._nonce_source = nonce_source or os.urandom
        self._issued: dict[str, Challenge] = {}
        self._consumed: set[str] = set()

    def issue(self) -> Challenge:
        now = int(self._clock())
        attempt = 0
        candidate = ''
        while True:
            raw = self._nonce_source(16)
            if not isinstance(raw, (bytes, bytearray)) or len(raw) < 16:
                raise FreshnessError('nonce source is too short')
            candidate = bytes(raw)[:16].hex()
            if attempt:
                candidate = hashlib.sha256(candidate.encode() + str(attempt).encode()).hexdigest()[:32]
            if candidate not in self._issued:
                break
            attempt += 1
        challenge = Challenge(candidate, now, now + self._ttl)
        self._issued[candidate] = challenge
        return challenge

    def consume(self, challenge_id: str) -> Challenge:
        if not isinstance(challenge_id, str) or _CHALLENGE_RE.fullmatch(challenge_id) is None:
            raise FreshnessError('challenge is unknown')
        challenge = self._issued.get(challenge_id)
        if challenge is None:
            raise FreshnessError('challenge is unknown')
        if challenge_id in self._consumed:
            raise FreshnessError('challenge is already consumed')
        if int(self._clock()) > challenge.expires_at:
            raise FreshnessError('challenge is expired')
        self._consumed.add(challenge_id)
        return challenge

    @property
    def issued(self) -> Iterable[Challenge]:
        return tuple(self._issued.values())


def seal_attestation(
    attestation: ProofAttestation,
    *,
    key_id: str,
    secret: bytes,
    challenge: Challenge,
) -> SealedAttestation:
    if not isinstance(challenge, Challenge) or _CHALLENGE_RE.fullmatch(challenge.challenge_id) is None:
        raise FreshnessError('challenge is invalid')
    if not isinstance(key_id, str) or _ID_RE.fullmatch(key_id) is None:
        raise FreshnessError('key id is invalid')
    material = _validate_secret(secret)
    digest = _attestation_digest(attestation)
    return SealedAttestation(
        SCHEMA,
        challenge.challenge_id,
        key_id,
        digest,
        _seal(material, challenge.challenge_id, digest, key_id),
    )


def verify_sealed_attestation(
    sealed: SealedAttestation,
    *,
    attestation: ProofAttestation,
    expected_challenge_id: str,
    key_resolver: Callable[[str], bytes | None],
    expected_key_id: str | None = None,
) -> ProofAttestation:
    if not isinstance(sealed, SealedAttestation):
        raise FreshnessError('sealed attestation is invalid')
    if not isinstance(expected_challenge_id, str) or _CHALLENGE_RE.fullmatch(expected_challenge_id) is None:
        raise FreshnessError('expected challenge is invalid')
    if sealed.challenge_id != expected_challenge_id:
        raise FreshnessError('seal is bound to a different challenge')
    if expected_key_id is not None and sealed.key_id != expected_key_id:
        raise FreshnessError('key identity mismatch')
    digest = _attestation_digest(attestation)
    if digest != sealed.attestation_digest:
        raise FreshnessError('seal is bound to a different attestation')
    try:
        secret = key_resolver(sealed.key_id)
    except Exception as exc:
        raise FreshnessError('signing key resolver failed') from exc
    if secret is None:
        raise FreshnessError('signing key unavailable')
    material = _validate_secret(secret)
    expected = _seal(material, sealed.challenge_id, sealed.attestation_digest, sealed.key_id)
    if not hmac.compare_digest(expected, sealed.signature):
        raise FreshnessError('sealed attestation signature mismatch')
    return attestation
