"""Tests for the evidence-aging probe corpus.

Old evidence is not fresh evidence: a valid digest vouches for
integrity, never for age. These tests pin the corpus shape (10 attack
probes across 3 families, 3 benign controls), the record semantics, the
freshness check, the fail-closed gate, batch unit-denial, and restamp
detection.
"""

import hashlib
import unittest

import evidence_aging_probes as eap

EXPECTED_PROBE_NAMES = (
    # evidence-decay
    "decay-stale-attestation",
    "decay-expired-scan",
    "decay-restamped-approval",
    "decay-stale-allowance",
    # freshness-checks
    "freshness-missing-timestamp",
    "freshness-unparseable-timestamp",
    "freshness-future-dated",
    # aging-gates
    "aging-unbounded-window",
    "aging-stale-through-digest-only-gate",
    "aging-mixed-batch",
)

EXPECTED_BENIGN_NAMES = (
    "benign-fresh-evidence",
    "benign-at-boundary",
    "benign-reverified",
)

EXPECTED_FAMILY_COUNTS = {
    "evidence-decay": (4, 1),  # (attacks, benign)
    "freshness-checks": (3, 1),
    "aging-gates": (3, 1),
}

REQUIRED_KEYS = ("probe", "family", "attack", "gate_interaction", "expected", "reason")

# Every attack probe's gate interaction must name an active deny-side
# check -- framing the attack must never read as a defense.
DENY_SIDE_KEYWORDS = (
    "denies",
    "denied",
    "deny",
    "quarantine",
    "quarantined",
    "quarantines",
    "blocks",
    "refuses",
    "never",
    "fail closed",
)

DAY = 86400
# Fixed reference time for every test: the module never reads the wall
# clock, and neither do the tests.
AS_OF = 1_800_000_000


def _payload_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _rec(**kwargs: object) -> "eap.EvidenceRecord":
    params: dict[str, object] = {
        "evidence_id": "ev-001",
        "kind": "attestation",
        "observed_ts": AS_OF - 3600,
        "payload_digest": _payload_digest("payload"),
        "issuer": "issuer-1",
        "max_age_seconds": DAY,
    }
    params.update(kwargs)
    return eap.build_record(**params)  # type: ignore[arg-type]


def _bad_record(**kwargs: object) -> "eap.EvidenceRecord":
    """Build a record whose digest does not recompute.

    The constructor fail-closes, so the bad record is built via
    ``object.__new__`` to exercise ``verify_record``'s return path.
    """
    good = _rec(**kwargs)
    bad = object.__new__(eap.EvidenceRecord)
    object.__setattr__(bad, "evidence_id", good.evidence_id)
    object.__setattr__(bad, "kind", good.kind)
    object.__setattr__(bad, "observed_ts", good.observed_ts)
    object.__setattr__(bad, "payload_digest", good.payload_digest)
    object.__setattr__(bad, "issuer", good.issuer)
    object.__setattr__(bad, "max_age_seconds", good.max_age_seconds)
    object.__setattr__(bad, "digest", "sha256:" + "0" * 64)
    return bad


class CorpusShapeTest(unittest.TestCase):
    def test_attack_probe_names(self) -> None:
        self.assertEqual(eap.probe_names(), EXPECTED_PROBE_NAMES)

    def test_benign_names(self) -> None:
        self.assertEqual(eap.benign_names(), EXPECTED_BENIGN_NAMES)

    def test_required_keys(self) -> None:
        for probe in (*eap.EVIDENCE_AGING_PROBES, *eap.EVIDENCE_AGING_BENIGN):
            for key in REQUIRED_KEYS:
                self.assertIn(key, probe, probe["probe"])
                self.assertTrue(probe[key], f"{probe['probe']}.{key} is empty")

    def test_names_unique(self) -> None:
        names = [p["probe"] for p in (*eap.EVIDENCE_AGING_PROBES, *eap.EVIDENCE_AGING_BENIGN)]
        self.assertEqual(len(names), len(set(names)))

    def test_family_counts(self) -> None:
        for family, (attacks, benign) in EXPECTED_FAMILY_COUNTS.items():
            items = eap.probes_by_family(family)
            self.assertEqual(len(items), attacks + benign, family)
            self.assertEqual(
                sum(1 for p in items if p["expected"] == "deny"), attacks, family
            )
            self.assertEqual(
                sum(1 for p in items if p["expected"] == "allow"), benign, family
            )

    def test_expected_outcomes(self) -> None:
        outcomes = eap.expected_outcomes()
        self.assertEqual(len(outcomes), 13)
        for name in EXPECTED_PROBE_NAMES:
            self.assertEqual(outcomes[name], "deny", name)
        for name in EXPECTED_BENIGN_NAMES:
            self.assertEqual(outcomes[name], "allow", name)

    def test_deny_side_keyword(self) -> None:
        for probe in eap.EVIDENCE_AGING_PROBES:
            text = (
                probe["gate_interaction"] + " " + probe["reason"]
            ).lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                f"{probe['probe']} has no deny-side keyword",
            )

    def test_probe_by_name(self) -> None:
        probe = eap.probe_by_name("decay-expired-scan")
        self.assertEqual(probe["family"], "evidence-decay")
        self.assertEqual(probe["expected"], "deny")
        with self.assertRaises(KeyError):
            eap.probe_by_name("no-such-probe")

    def test_version_pin(self) -> None:
        self.assertEqual(eap.EVIDENCE_AGING_VERSION, "evidence-aging.v1")

    def test_main_runs(self) -> None:
        eap.main()


class RecordSemanticsTest(unittest.TestCase):
    def test_round_trip(self) -> None:
        record = _rec()
        self.assertTrue(eap.verify_record(record))

    def test_tampered_digest_fails_verify(self) -> None:
        self.assertFalse(eap.verify_record(_bad_record()))

    def test_constructor_fail_closes_on_tamper(self) -> None:
        good = _rec()
        with self.assertRaises(ValueError):
            eap.EvidenceRecord(
                evidence_id=good.evidence_id,
                kind=good.kind,
                observed_ts=good.observed_ts,
                payload_digest=good.payload_digest,
                issuer=good.issuer,
                max_age_seconds=good.max_age_seconds,
                digest="sha256:" + "0" * 64,
            )

    def test_bad_kind_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _rec(kind="vibes")

    def test_bad_max_age_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _rec(max_age_seconds=0)
        with self.assertRaises(ValueError):
            _rec(max_age_seconds=-5)

    def test_rfc3339_timestamp_parses(self) -> None:
        record = _rec(observed_ts="2026-10-01T00:00:00Z")
        self.assertTrue(eap.verify_record(record))
        status = eap.freshness(record, 1_790_000_000)
        self.assertIn(status["status"], eap.FRESHNESS_STATUSES)


class FreshnessTest(unittest.TestCase):
    def test_fresh(self) -> None:
        result = eap.freshness(_rec(), AS_OF)
        self.assertEqual(result["status"], "fresh")
        self.assertEqual(result["age_seconds"], 3600)

    def test_stale(self) -> None:
        record = _rec(observed_ts=AS_OF - 2 * DAY)
        result = eap.freshness(record, AS_OF)
        self.assertEqual(result["status"], "stale")
        self.assertGreater(result["age_seconds"], DAY)

    def test_boundary_is_fresh(self) -> None:
        record = _rec(observed_ts=AS_OF - DAY)
        result = eap.freshness(record, AS_OF)
        self.assertEqual(result["status"], "fresh")

    def test_future_dated(self) -> None:
        record = _rec(observed_ts=AS_OF + 60)
        result = eap.freshness(record, AS_OF)
        self.assertEqual(result["status"], "future_dated")
        self.assertLess(result["age_seconds"], 0)

    def test_uncheckable_missing(self) -> None:
        record = _rec(observed_ts=None)
        result = eap.freshness(record, AS_OF)
        self.assertEqual(result["status"], "uncheckable")
        self.assertIsNone(result["age_seconds"])

    def test_uncheckable_malformed(self) -> None:
        record = _rec(observed_ts="soon-ish")
        result = eap.freshness(record, AS_OF)
        self.assertEqual(result["status"], "uncheckable")

    def test_non_numeric_as_of_rejected(self) -> None:
        with self.assertRaises(TypeError):
            eap.freshness(_rec(), "yesterday")


class GateTest(unittest.TestCase):
    def test_fresh_allowed(self) -> None:
        decision, findings = eap.gate_evidence(_rec(), AS_OF)
        self.assertEqual(decision, "allow")
        self.assertEqual(findings, ())

    def test_stale_denied(self) -> None:
        decision, findings = eap.gate_evidence(_rec(observed_ts=AS_OF - 2 * DAY), AS_OF)
        self.assertEqual(decision, "deny")
        self.assertEqual(findings, ("evidence-stale",))

    def test_uncheckable_denied(self) -> None:
        decision, findings = eap.gate_evidence(_rec(observed_ts=None), AS_OF)
        self.assertEqual(decision, "deny")
        self.assertEqual(findings, ("evidence-uncheckable",))

    def test_future_dated_denied(self) -> None:
        decision, findings = eap.gate_evidence(_rec(observed_ts=AS_OF + 60), AS_OF)
        self.assertEqual(decision, "deny")
        self.assertEqual(findings, ("evidence-future-dated",))

    def test_digest_mismatch_denied_first(self) -> None:
        # Digest check runs before every other check: even a stale
        # record with a broken digest is reported as a digest problem.
        decision, findings = eap.gate_evidence(
            _bad_record(observed_ts=AS_OF - 2 * DAY), AS_OF
        )
        self.assertEqual(decision, "deny")
        self.assertEqual(findings, ("evidence-digest-mismatch",))

    def test_unbounded_window_denied(self) -> None:
        record = _rec(max_age_seconds=10 * 365 * DAY)
        decision, findings = eap.gate_evidence(record, AS_OF, ceiling_seconds=DAY)
        self.assertEqual(decision, "deny")
        self.assertEqual(findings, ("evidence-unbounded",))

    def test_window_within_ceiling_allowed(self) -> None:
        record = _rec(max_age_seconds=DAY)
        decision, _ = eap.gate_evidence(record, AS_OF, ceiling_seconds=7 * DAY)
        self.assertEqual(decision, "allow")

    def test_findings_in_fixed_vocabulary(self) -> None:
        cases = [
            _bad_record(),
            _rec(observed_ts=None),
            _rec(observed_ts=AS_OF + 60),
            _rec(observed_ts=AS_OF - 2 * DAY),
            _rec(max_age_seconds=10 * 365 * DAY),
        ]
        for record in cases:
            decision, findings = eap.gate_evidence(
                record, AS_OF, ceiling_seconds=DAY
            )
            self.assertEqual(decision, "deny")
            self.assertEqual(len(findings), 1)
            self.assertIn(findings[0], eap.FINDING_KINDS)


class BatchTest(unittest.TestCase):
    def test_all_fresh_allowed(self) -> None:
        allowed, denied, findings = eap.gate_batch([_rec(), _rec()], AS_OF)
        self.assertTrue(allowed)
        self.assertEqual(denied, ())
        self.assertEqual(findings, {})

    def test_one_stale_denies_batch(self) -> None:
        records = [_rec(), _rec(observed_ts=AS_OF - 2 * DAY), _rec()]
        allowed, denied, findings = eap.gate_batch(records, AS_OF)
        self.assertFalse(allowed)
        self.assertEqual(denied, (1,))
        self.assertEqual(findings, {1: "evidence-stale"})

    def test_malformed_item_denies_batch(self) -> None:
        allowed, denied, findings = eap.gate_batch([_rec(), "not-a-record"], AS_OF)
        self.assertFalse(allowed)
        self.assertEqual(denied, (1,))
        self.assertEqual(findings, {1: "evidence-uncheckable"})

    def test_empty_batch_allowed(self) -> None:
        allowed, denied, findings = eap.gate_batch([], AS_OF)
        self.assertTrue(allowed)
        self.assertEqual(denied, ())
        self.assertEqual(findings, {})


class RestampTest(unittest.TestCase):
    def test_restamp_detected(self) -> None:
        old = _rec(observed_ts=AS_OF - 2 * DAY)
        new = _rec(observed_ts=AS_OF - 3600)
        self.assertEqual(eap.detect_restamp(old, new), "evidence-restamped")

    def test_genuine_reobservation_not_restamp(self) -> None:
        old = _rec(observed_ts=AS_OF - 2 * DAY)
        new = _rec(
            observed_ts=AS_OF - 3600,
            payload_digest=_payload_digest("new observation"),
        )
        self.assertIsNone(eap.detect_restamp(old, new))

    def test_different_ids_not_restamp(self) -> None:
        old = _rec(observed_ts=AS_OF - 2 * DAY)
        new = _rec(observed_ts=AS_OF - 3600, evidence_id="ev-002")
        self.assertIsNone(eap.detect_restamp(old, new))

    def test_uncheckable_timestamp_not_restamp(self) -> None:
        old = _rec(observed_ts=AS_OF - 2 * DAY)
        new = _rec(observed_ts=None)
        self.assertIsNone(eap.detect_restamp(old, new))

    def test_same_timestamp_not_restamp(self) -> None:
        record = _rec()
        self.assertIsNone(eap.detect_restamp(record, record))

    def test_never_raises(self) -> None:
        self.assertIsNone(eap.detect_restamp("x", None))


class StandaloneImportTest(unittest.TestCase):
    def test_jcs_fallback_digest_format(self) -> None:
        digest = _payload_digest("x")
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(len(digest), 71)


if __name__ == "__main__":
    unittest.main()
