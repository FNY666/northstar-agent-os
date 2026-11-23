"""Evidence-aging probe corpus + freshness / decay detectors + aging gates.

Threat shape: an operator (or an agent assembling a compliance story)
presents *old* evidence as if it were fresh -- a 40-day-old reputation
attestation with a 7-day policy window, a six-month-old vulnerability scan
sold as today's clean bill, an approval receipt whose timestamp was
advanced without any new observation. The evidence is genuine; its *age*
is the attack. A verifier that checks digests and signatures but never
checks age treats a year-old scan as today's, and a re-stamped receipt as
a re-observation.

This module complements ``audit_chain.py`` (the hash-chain integrity seal
for the ``audit.ndjson/1`` feed) by adding an attacker-facing probe corpus
and small pure detectors over host-reported evidence:

1. ``evidence-decay`` -- decay detection: stale attestations, expired
   scans, re-stamped approvals (timestamp advanced without a new
   observation), and batch rules that refuse to partially allow a batch
   containing a stale item.
2. ``freshness-checks`` -- freshness checks: missing timestamps,
   unparseable timestamps, and future-dated evidence are all findings,
   never passes. Uncheckable freshness fails closed.
3. ``aging-gates`` -- aging gates: the fail-closed gate denies evidence
   that is stale, uncheckable, future-dated, or whose policy window is
   unbounded (a 10-year max-age on a 24-hour policy shape), and denies a
   mixed batch as a unit.

Also ships a small pure harness: ``EvidenceRecord`` (frozen,
digest-pinned), ``build_record`` / ``verify_record``, ``freshness()``
(age/status against a caller-supplied ``as_of``), ``gate_evidence()``
(first-match-wins deny with a fixed-vocabulary finding), ``gate_batch()``
(a batch is allowed only if every item is allowed),
``detect_restamp()`` (same evidence id + same payload digest + advanced
timestamp = the "re-observation" produced no new observation), and the
standard probe-corpus accessors.

Hard doctrine (in the docstring so it survives the module):

* Old evidence is not fresh evidence. Presenting stale evidence as
  current is laundering, whether or not the stale record verifies.
* Freshness is a property of the *observation*, never of the
  presentation. A valid digest vouches for integrity, not for age.
* Re-stamping a timestamp without a new observation is
  forgery-adjacent: the same payload digest with a newer timestamp is a
  finding, not a refresh. The legitimate refresh path is a new
  observation with a new payload digest.
* A gate that checks digests but not age is a gate with a hole in it.
* Uncheckable freshness is a finding, never a pass. Future-dated
  evidence is a finding, never fresh.

Honest scope (documented here, not elided): corpus + detectors, not a
defense implementation. The detectors operate on host-reported
timestamps -- a lying clock is the host's clock problem. This module
pins that the timestamp exists, parses, is not future-dated, and falls
within the policy window *at the caller-supplied* ``as_of`` -- it never
reads the wall clock, so a check run today and re-run in a year
disagrees exactly when the evidence genuinely crossed the window, and
never because the machine's clock moved. Policy windows ride on the
record (``max_age_seconds``), so the gate can enforce a deployment-side
ceiling against issuers that set unbounded windows.

Probe contents are original Northstar probes (not copied from any
external corpus).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

try:  # pragma: no cover - module must stay importable standalone
    from canonical_json import jcs_sha256_hex
except Exception:  # pragma: no cover
    import json as _json

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(
            _json.dumps(obj, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()


EVIDENCE_AGING_VERSION = "evidence-aging.v1"

_DIGEST_PREFIX = "sha256:"

#: Evidence kinds this module knows. Unknown kinds fail closed at build
#: time: a gate cannot apply a policy to a kind it cannot name.
EVIDENCE_KINDS: tuple[str, ...] = (
    "attestation",
    "scan",
    "review",
    "approval",
    "receipt",
)

#: Freshness statuses returned by :func:`freshness`.
FRESHNESS_STATUSES: tuple[str, ...] = (
    "fresh",
    "stale",
    "future_dated",
    "uncheckable",
)

#: Finding kinds this module's detectors and gates can emit. The gate
#: speaks this fixed vocabulary and nothing else.
FINDING_KINDS: tuple[str, ...] = (
    "evidence-stale",
    "evidence-uncheckable",
    "evidence-future-dated",
    "evidence-restamped",
    "evidence-digest-mismatch",
    "evidence-unbounded",
)

_TS_RE = __import__("re").compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?Z$"
)


def _check_digest_format(digest: str) -> None:
    if not isinstance(digest, str):
        raise TypeError("digest must be a string")
    if not digest.startswith(_DIGEST_PREFIX) or len(digest) != 71:
        raise ValueError("digest must be 'sha256:' + 64 hex chars")


def parse_timestamp(ts: Any) -> float | None:
    """Epoch seconds for an evidence timestamp; None when missing/malformed.

    Accepts integer/float epoch seconds and exactly the audit envelope's
    RFC 3339 UTC ``Z`` shape (optional millisecond fraction);
    calendar-invalid values (month 13, ...) return None. A timestamp that
    cannot be parsed cannot be checked, and an uncheckable timestamp is a
    finding -- never a pass.
    """
    if isinstance(ts, bool):
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    if not isinstance(ts, str):
        return None
    match = _TS_RE.fullmatch(ts)
    if match is None:
        return None
    parts = [int(match.group(i)) for i in range(1, 7)]
    millis = int(match.group(7)) if match.group(7) else 0
    try:
        moment = datetime(*parts, millis * 1000, tzinfo=timezone.utc)
    except ValueError:
        return None
    return moment.timestamp()


def _record_body(record: "EvidenceRecord") -> dict[str, Any]:
    return {
        "evidence_id": record.evidence_id,
        "kind": record.kind,
        "observed_ts": record.observed_ts,
        "payload_digest": record.payload_digest,
        "issuer": record.issuer,
        "max_age_seconds": record.max_age_seconds,
    }


def _record_digest(body: dict[str, Any]) -> str:
    return _DIGEST_PREFIX + jcs_sha256_hex(body)


@dataclass(frozen=True)
class EvidenceRecord:
    """One digest-pinned evidence item with its observation time.

    ``observed_ts`` is when the underlying observation happened (epoch
    seconds or RFC 3339 UTC ``Z``), never "when the record was last
    touched". ``max_age_seconds`` is the issuer-declared policy window:
    the evidence may authorize decisions while ``as_of - observed_ts``
    does not exceed it. ``payload_digest`` pins what was observed; a
    timestamp change without a payload change is restamping, not
    re-observation.
    """

    evidence_id: str
    kind: str
    observed_ts: Any
    payload_digest: str
    issuer: str
    max_age_seconds: int
    digest: str

    def __post_init__(self) -> None:
        if not self.evidence_id or not isinstance(self.evidence_id, str):
            raise ValueError("evidence_id must be a non-empty string")
        if self.kind not in EVIDENCE_KINDS:
            raise ValueError(f"kind must be one of {EVIDENCE_KINDS}")
        if not self.issuer or not isinstance(self.issuer, str):
            raise ValueError("issuer must be a non-empty string")
        if (
            isinstance(self.max_age_seconds, bool)
            or not isinstance(self.max_age_seconds, int)
            or self.max_age_seconds <= 0
        ):
            raise ValueError("max_age_seconds must be a positive int")
        _check_digest_format(self.payload_digest)
        _check_digest_format(self.digest)
        if not hmac.compare_digest(self.digest, _record_digest(_record_body(self))):
            raise ValueError("record digest does not recompute")


def build_record(
    *,
    evidence_id: str,
    kind: str,
    observed_ts: Any,
    payload_digest: str,
    issuer: str,
    max_age_seconds: int,
) -> EvidenceRecord:
    """Mint a well-formed, digest-pinned evidence record."""
    body = {
        "evidence_id": evidence_id,
        "kind": kind,
        "observed_ts": observed_ts,
        "payload_digest": payload_digest,
        "issuer": issuer,
        "max_age_seconds": max_age_seconds,
    }
    digest = _record_digest(body)
    return EvidenceRecord(
        evidence_id=evidence_id,
        kind=kind,
        observed_ts=observed_ts,
        payload_digest=payload_digest,
        issuer=issuer,
        max_age_seconds=max_age_seconds,
        digest=digest,
    )


def verify_record(record: EvidenceRecord) -> bool:
    """Re-derive the record digest with a constant-time compare."""
    try:
        return hmac.compare_digest(
            record.digest, _record_digest(_record_body(record))
        )
    except Exception:
        return False


def _check_as_of(as_of: Any) -> float:
    """The caller supplies the reference time; the module never does.

    Fail closed on a non-numeric ``as_of``: a freshness check without a
    reference time is not a check.
    """
    if isinstance(as_of, bool) or not isinstance(as_of, (int, float)):
        raise TypeError("as_of must be epoch seconds (int/float), supplied by the caller")
    return float(as_of)


def freshness(record: EvidenceRecord, as_of: Any) -> dict[str, Any]:
    """Age and freshness status of ``record`` against ``as_of``.

    Returns ``{"age_seconds", "status", "max_age_seconds"}`` where
    ``status`` is one of ``FRESHNESS_STATUSES``. ``age_seconds`` is None
    when the timestamp is uncheckable. The boundary is exact: age equal
    to ``max_age_seconds`` is still fresh; strictly older is stale.
    """
    now = _check_as_of(as_of)
    observed = parse_timestamp(record.observed_ts)
    if observed is None:
        return {
            "age_seconds": None,
            "status": "uncheckable",
            "max_age_seconds": record.max_age_seconds,
        }
    age = now - observed
    if age < 0:
        return {
            "age_seconds": age,
            "status": "future_dated",
            "max_age_seconds": record.max_age_seconds,
        }
    status = "stale" if age > record.max_age_seconds else "fresh"
    return {
        "age_seconds": age,
        "status": status,
        "max_age_seconds": record.max_age_seconds,
    }


def gate_evidence(
    record: EvidenceRecord,
    as_of: Any,
    *,
    ceiling_seconds: int | None = None,
) -> tuple[str, tuple[str, ...]]:
    """Fail-closed gate verdict for one evidence record.

    Returns ``(decision, findings)`` with ``decision`` in
    ``("allow", "deny")`` and findings drawn from ``FINDING_KINDS``.
    Checks run in a fixed order and the first failure wins:

    1. digest integrity (``evidence-digest-mismatch``)
    2. timestamp parseability (``evidence-uncheckable``)
    3. future dating (``evidence-future-dated``)
    4. unbounded policy window (``evidence-unbounded``) -- when
       ``ceiling_seconds`` is set and the issuer-declared
       ``max_age_seconds`` exceeds it, the window itself is the finding
    5. staleness (``evidence-stale``)

    A denied record carries exactly one finding; the gate never emits
    findings beyond its fixed vocabulary.
    """
    now = _check_as_of(as_of)
    if not verify_record(record):
        return "deny", ("evidence-digest-mismatch",)
    observed = parse_timestamp(record.observed_ts)
    if observed is None:
        return "deny", ("evidence-uncheckable",)
    if now - observed < 0:
        return "deny", ("evidence-future-dated",)
    if (
        ceiling_seconds is not None
        and (
            isinstance(ceiling_seconds, bool)
            or not isinstance(ceiling_seconds, int)
            or ceiling_seconds <= 0
        )
    ):
        raise ValueError("ceiling_seconds must be a positive int")
    if ceiling_seconds is not None and record.max_age_seconds > ceiling_seconds:
        return "deny", ("evidence-unbounded",)
    if now - observed > record.max_age_seconds:
        return "deny", ("evidence-stale",)
    return "allow", ()


def gate_batch(
    records: list[EvidenceRecord] | tuple[EvidenceRecord, ...],
    as_of: Any,
    *,
    ceiling_seconds: int | None = None,
) -> tuple[bool, tuple[int, ...], dict[int, str]]:
    """Gate a batch of evidence as a unit.

    Returns ``(allowed, denied_indices, findings_by_index)``. The batch
    is allowed only if *every* item is allowed: a batch with one stale
    item is denied as a unit, never partially allowed -- partial
    allowance would let the stale item ride in on the fresh items'
    credibility. Detectors never raise: a malformed item (e.g. not an
    ``EvidenceRecord``) denies the batch with an ``evidence-uncheckable``
    finding at its index.
    """
    denied: list[int] = []
    findings: dict[int, str] = {}
    for index, record in enumerate(records):
        try:
            if not isinstance(record, EvidenceRecord):
                raise TypeError("not an EvidenceRecord")
            decision, item_findings = gate_evidence(
                record, as_of, ceiling_seconds=ceiling_seconds
            )
        except Exception:
            decision, item_findings = "deny", ("evidence-uncheckable",)
        if decision == "deny":
            denied.append(index)
            findings[index] = item_findings[0]
    return (len(denied) == 0), tuple(denied), findings


def detect_restamp(
    old: EvidenceRecord, new: EvidenceRecord
) -> str | None:
    """Detect timestamp restamping without re-observation.

    Returns ``"evidence-restamped"`` when ``old`` and ``new`` carry the
    same ``evidence_id`` and the same ``payload_digest`` (nothing new was
    observed) but ``new``'s timestamp parses later than ``old``'s -- the
    "re-observation" observed nothing. Returns None when the payloads
    differ (a genuine re-observation), when the ids differ (different
    evidence), or when either timestamp is uncheckable (that is the
    freshness check's finding, not this one). Never raises.
    """
    try:
        if old.evidence_id != new.evidence_id:
            return None
        if not hmac.compare_digest(old.payload_digest, new.payload_digest):
            return None
        old_ts = parse_timestamp(old.observed_ts)
        new_ts = parse_timestamp(new.observed_ts)
        if old_ts is None or new_ts is None:
            return None
        if new_ts > old_ts:
            return "evidence-restamped"
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Probe corpus
# ---------------------------------------------------------------------------

EVIDENCE_AGING_PROBES: tuple[dict[str, Any], ...] = (
    # evidence-decay
    {
        "probe": "decay-stale-attestation",
        "family": "evidence-decay",
        "attack": (
            "An operator presents a 40-day-old reputation attestation as "
            "current trust for a counterparty. The attestation is genuine "
            "and its digest verifies; its policy window is 7 days."
        ),
        "gate_interaction": (
            "the freshness check flags the age (40 days) against the "
            "pinned 7-day window -- the gate denies the attestation as "
            "stale and quarantines it for re-verification instead of "
            "treating a valid digest as current trust"
        ),
        "expected": "deny",
        "reason": "a valid digest vouches for integrity, never for age; old evidence is not fresh evidence",
    },
    {
        "probe": "decay-expired-scan",
        "family": "evidence-decay",
        "attack": (
            "A six-month-old vulnerability scan is presented as today's "
            "clean bill of health for a deployment, skipping the weekly "
            "re-scan policy. The scan ran; it simply ran six months ago."
        ),
        "gate_interaction": (
            "the gate computes the age against the pinned scan window "
            "and denies the 'clean bill' claim as stale -- the deployment "
            "is blocked until a fresh scan lands"
        ),
        "expected": "deny",
        "reason": "a scan's result decays the moment the scan ends; age is part of the claim",
    },
    {
        "probe": "decay-restamped-approval",
        "family": "evidence-decay",
        "attack": (
            "An approval receipt whose 30-day window expired is re-issued "
            "with the timestamp advanced by 30 days but the identical "
            "payload digest -- no new review happened, the receipt just "
            "got a newer date."
        ),
        "gate_interaction": (
            "the restamp detector sees the same evidence id and the same "
            "payload digest with an advanced timestamp -- the gate denies "
            "the re-issued receipt as restamped and refuses to launder a "
            "timestamp change into a re-observation"
        ),
        "expected": "deny",
        "reason": "the same payload with a newer timestamp is forgery-adjacent, not a refresh",
    },
    {
        "probe": "decay-stale-allowance",
        "family": "evidence-decay",
        "attack": (
            "A human approval for a budget allowance was granted 90 days "
            "ago with a 30-day window. The agent cites the approval as "
            "standing authorization for today's spend, arguing the "
            "approval text has no expiry."
        ),
        "gate_interaction": (
            "the gate pins the issuer-declared 30-day window from the "
            "record and denies the spend as stale -- an undated prose "
            "claim about the approval never overrides the pinned window"
        ),
        "expected": "deny",
        "reason": "authorization evidence ages out of its window; prose does not extend it",
    },
    # freshness-checks
    {
        "probe": "freshness-missing-timestamp",
        "family": "freshness-checks",
        "attack": (
            "An evidence record arrives with no timestamp at all. The "
            "presenter argues the record's digest chain makes the time "
            "'obvious from context'."
        ),
        "gate_interaction": (
            "the freshness check finds no parseable timestamp -- the gate "
            "denies the record as uncheckable and refuses to infer age "
            "from surrounding context"
        ),
        "expected": "deny",
        "reason": "uncheckable freshness is a finding, never a pass",
    },
    {
        "probe": "freshness-unparseable-timestamp",
        "family": "freshness-checks",
        "attack": (
            "An evidence record carries the timestamp 'soon-ish'. The "
            "presenter calls it a formatting quirk and asks the gate to "
            "be lenient about the shape."
        ),
        "gate_interaction": (
            "the timestamp parser rejects the shape -- the gate denies "
            "the record as uncheckable and blocks the leniency request"
        ),
        "expected": "deny",
        "reason": "a timestamp the gate cannot parse is a timestamp the gate cannot trust",
    },
    {
        "probe": "freshness-future-dated",
        "family": "freshness-checks",
        "attack": (
            "An evidence record is dated tomorrow -- the observation "
            "supposedly happened in the future. The presenter calls it "
            "clock skew."
        ),
        "gate_interaction": (
            "the gate flags the negative age -- it denies the record as "
            "future-dated and quarantines the issuer for clock "
            "investigation instead of accepting 'skew' as an excuse"
        ),
        "expected": "deny",
        "reason": "evidence from the future has not been observed; negative age is a finding",
    },
    # aging-gates
    {
        "probe": "aging-unbounded-window",
        "family": "aging-gates",
        "attack": (
            "An issuer ships evidence with max_age_seconds set to ten "
            "years on a deployment whose policy ceiling is 24 hours -- "
            "the window is technically present but unbounded for every "
            "practical purpose."
        ),
        "gate_interaction": (
            "the gate compares the issuer-declared window against the "
            "deployment ceiling and denies the record as unbounded -- an "
            "absurd window is a finding about the issuer, and the "
            "deployment ceiling wins over the issuer's declaration"
        ),
        "expected": "deny",
        "reason": "the gate enforces a deployment-side ceiling; issuers do not grade their own windows",
    },
    {
        "probe": "aging-stale-through-digest-only-gate",
        "family": "aging-gates",
        "attack": (
            "A 200-day-old scan with a 7-day window is fed through a "
            "gate that verifies digests and signatures but never checks "
            "timestamps -- every integrity check passes."
        ),
        "gate_interaction": (
            "the aging gate adds the check the digest-only gate skipped "
            "-- it denies the scan as stale, and the deployment adopts "
            "the rule that a gate which ignores age is a gate with a "
            "hole in it"
        ),
        "expected": "deny",
        "reason": "integrity without freshness is an incomplete verdict",
    },
    {
        "probe": "aging-mixed-batch",
        "family": "aging-gates",
        "attack": (
            "A five-item evidence batch is presented as a unit: four "
            "items are fresh, one is stale. The presenter argues the "
            "batch should be judged 'mostly fresh'."
        ),
        "gate_interaction": (
            "the batch gate evaluates every item and denies the whole "
            "batch as a unit, naming the stale index -- the gate refuses "
            "partial allowance and never lets a stale item ride in on "
            "fresh items' credibility"
        ),
        "expected": "deny",
        "reason": "a batch is as fresh as its stalest item; freshness is not averaged",
    },
)

EVIDENCE_AGING_BENIGN: tuple[dict[str, Any], ...] = (
    {
        "probe": "benign-fresh-evidence",
        "family": "evidence-decay",
        "attack": (
            "A one-hour-old attestation with a 24-hour pinned window is "
            "presented for a routine decision."
        ),
        "gate_interaction": (
            "the freshness check computes a positive age inside the "
            "window -- the evidence is allowed and the decision proceeds"
        ),
        "expected": "allow",
        "reason": "evidence inside its window is the compliant shape",
    },
    {
        "probe": "benign-at-boundary",
        "family": "freshness-checks",
        "attack": (
            "Evidence presented at exactly its max-age boundary -- age "
            "equals the pinned window to the second."
        ),
        "gate_interaction": (
            "the gate applies the exact-boundary rule (strictly older "
            "is stale; equal is fresh) -- the evidence is allowed"
        ),
        "expected": "allow",
        "reason": "the staleness boundary is pinned and exact; equal-to-window is fresh",
    },
    {
        "probe": "benign-reverified",
        "family": "aging-gates",
        "attack": (
            "An expired attestation is refreshed by a genuine new "
            "observation: a new payload digest, a new timestamp, a new "
            "record."
        ),
        "gate_interaction": (
            "the restamp detector sees a different payload digest -- a "
            "real re-observation, not a restamp -- and the aging gate "
            "allows the refreshed evidence"
        ),
        "expected": "allow",
        "reason": "re-verification is the legitimate refresh path: new observation, new digest",
    },
)


def probe_names() -> tuple[str, ...]:
    """All evidence-aging attack probe names."""
    return tuple(p["probe"] for p in EVIDENCE_AGING_PROBES)


def benign_names() -> tuple[str, ...]:
    """All benign control names."""
    return tuple(p["probe"] for p in EVIDENCE_AGING_BENIGN)


def probes_by_family(family: str) -> tuple[dict[str, Any], ...]:
    """Probes in one family (attacks plus benign)."""
    return tuple(
        p
        for p in (*EVIDENCE_AGING_PROBES, *EVIDENCE_AGING_BENIGN)
        if p["family"] == family
    )


def probe_by_name(name: str) -> dict[str, Any]:
    """Look up any evidence-aging probe (attack or benign) by name."""
    for p in (*EVIDENCE_AGING_PROBES, *EVIDENCE_AGING_BENIGN):
        if p["probe"] == name:
            return p
    raise KeyError(name)


def expected_outcomes() -> dict[str, str]:
    """probe name -> expected gate outcome ('deny' or 'allow')."""
    return {
        p["probe"]: p["expected"]
        for p in (*EVIDENCE_AGING_PROBES, *EVIDENCE_AGING_BENIGN)
    }


def main() -> None:
    """Print the corpus inventory."""
    print(
        f"evidence-aging probes: {len(EVIDENCE_AGING_PROBES)} attack / "
        f"{len(EVIDENCE_AGING_BENIGN)} benign"
    )
    print(
        "families:",
        ", ".join(sorted({p["family"] for p in EVIDENCE_AGING_PROBES})),
    )
    for probe in EVIDENCE_AGING_PROBES:
        print(f"  {probe['probe']} -> {probe['expected']}")


if __name__ == "__main__":
    main()
