"""Tests for privilege_at_recall_probes."""

import hashlib
import unittest

import privilege_at_recall_probes as par


EXPECTED_PROBE_NAMES = (
    "recall-elevation",
    "recall-scope-expansion",
    "recall-purpose-drift",
    "recall-stale-authority",
    "retrieval-before-filter",
    "unfiltered-top-k",
    "filter-after-rank",
    "cross-tenant-recall",
    "cross-agent-no-grant",
    "untrusted-laundered",
)

EXPECTED_BENIGN_NAMES = (
    "benign-scoped-recall",
    "benign-filter-first",
    "benign-granted-cross-read",
)

FAMILY_COUNTS = {
    "privilege-at-recall": (4, 1),
    "identity-filtering": (3, 1),
    "recall-gates": (3, 1),
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


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _rec(**kwargs: object) -> "par.MemoryRecord":
    base: dict[str, object] = {
        "record_id": "r1",
        "payload_digest": _digest("payload"),
        "writer": "admission",
        "tenant": "acme",
        "owner_agent": "analyst-bot",
        "trust": "trusted",
        "scope": ("billing-read",),
        "max_privilege": 1,
        "grant": (),
        "authority_version": 1,
        "seq": 0,
        "prev_digest": "sha256:" + "00" * 32,
    }
    base.update(kwargs)
    return par.build_record(**base)  # type: ignore[arg-type]


def _req(**kwargs: object) -> "par.RecallRequest":
    base: dict[str, object] = {
        "caller_agent": "analyst-bot",
        "caller_tenant": "acme",
        "caller_privilege": 2,
        "purpose": "billing-read",
        "requires_trusted": True,
        "accepted_authority": 1,
    }
    base.update(kwargs)
    return par.build_request(**base)  # type: ignore[arg-type]


class CorpusShapeTests(unittest.TestCase):
    def test_probe_names_unique(self) -> None:
        names = par.probe_names() + par.benign_names()
        self.assertEqual(len(names), len(set(names)))

    def test_probe_counts(self) -> None:
        self.assertEqual(len(par.probe_names()), 10)
        self.assertEqual(len(par.benign_names()), 3)

    def test_expected_probe_names(self) -> None:
        self.assertEqual(tuple(sorted(par.probe_names())),
                         tuple(sorted(EXPECTED_PROBE_NAMES)))
        self.assertEqual(tuple(sorted(par.benign_names())),
                         tuple(sorted(EXPECTED_BENIGN_NAMES)))

    def test_required_keys(self) -> None:
        for probe in (*par.PRIVILEGE_AT_RECALL_PROBES, *par.PRIVILEGE_AT_RECALL_BENIGN):
            for key in REQUIRED_KEYS:
                self.assertIn(key, probe, probe["probe"])

    def test_family_counts(self) -> None:
        for family, (attacks, benign) in FAMILY_COUNTS.items():
            items = par.probes_by_family(family)
            self.assertEqual(
                sum(1 for p in items if p["expected"] == "deny"), attacks, family
            )
            self.assertEqual(
                sum(1 for p in items if p["expected"] == "allow"), benign, family
            )

    def test_expected_outcomes(self) -> None:
        outcomes = par.expected_outcomes()
        self.assertEqual(len(outcomes), 13)
        for name in EXPECTED_PROBE_NAMES:
            self.assertEqual(outcomes[name], "deny", name)
        for name in EXPECTED_BENIGN_NAMES:
            self.assertEqual(outcomes[name], "allow", name)

    def test_deny_side_keyword(self) -> None:
        for probe in par.PRIVILEGE_AT_RECALL_PROBES:
            text = (
                probe["gate_interaction"] + " " + probe["reason"]
            ).lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                f"{probe['probe']} has no deny-side keyword",
            )

    def test_attack_probes_name_attack(self) -> None:
        for probe in par.PRIVILEGE_AT_RECALL_PROBES:
            self.assertIsInstance(probe["attack"], str, probe["probe"])
            self.assertEqual(probe["expected"], "deny")

    def test_probe_by_name(self) -> None:
        probe = par.probe_by_name("cross-tenant-recall")
        self.assertEqual(probe["family"], "recall-gates")
        self.assertEqual(probe["expected"], "deny")
        with self.assertRaises(KeyError):
            par.probe_by_name("no-such-probe")

    def test_version_pin(self) -> None:
        self.assertEqual(par.PRIVILEGE_AT_RECALL_VERSION, "privilege-at-recall.v1")

    def test_main_runs(self) -> None:
        par.main()


class RecordSemanticsTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        self.assertTrue(par.verify_record(_rec()))

    def _bad_digest_record(self, record: "par.MemoryRecord") -> "par.MemoryRecord":
        """A record with a bad digest, bypassing the fail-closed
        constructor so verify_record's return path is exercised."""
        bad = object.__new__(par.MemoryRecord)
        object.__setattr__(bad, "record_id", record.record_id)
        object.__setattr__(bad, "payload_digest", record.payload_digest)
        object.__setattr__(bad, "writer", record.writer)
        object.__setattr__(bad, "tenant", record.tenant)
        object.__setattr__(bad, "owner_agent", record.owner_agent)
        object.__setattr__(bad, "trust", record.trust)
        object.__setattr__(bad, "scope", record.scope)
        object.__setattr__(bad, "max_privilege", record.max_privilege)
        object.__setattr__(bad, "grant", record.grant)
        object.__setattr__(bad, "authority_version", record.authority_version)
        object.__setattr__(bad, "seq", record.seq)
        object.__setattr__(bad, "prev_digest", record.prev_digest)
        object.__setattr__(bad, "digest", _digest("forged"))
        return bad

    def test_tamper_fail(self) -> None:
        bad = self._bad_digest_record(_rec())
        self.assertFalse(par.verify_record(bad))

    def test_bad_trust_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _rec(trust="sort-of-trusted")

    def test_bad_payload_digest_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _rec(payload_digest="not-a-digest")

    def test_negative_privilege_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _rec(max_privilege=-1)

    def test_request_round_trip(self) -> None:
        self.assertTrue(par.verify_request(_req()))

    def test_request_tamper_fail(self) -> None:
        req = _req()
        bad = par.RecallRequest(**{**req.__dict__, "digest": _digest("forged")})
        self.assertFalse(par.verify_request(bad))


class AuthorizeRecallTests(unittest.TestCase):
    def test_honest_allow(self) -> None:
        decision, finding = par.authorize_recall(_rec(), _req())
        self.assertEqual(decision, "allow")
        self.assertIsNone(finding)

    def test_cross_tenant_denied(self) -> None:
        decision, finding = par.authorize_recall(
            _rec(tenant="acme"), _req(caller_tenant="globex")
        )
        self.assertEqual(decision, "deny")
        self.assertEqual(finding, "recall-cross-tenant")

    def test_elevation_denied(self) -> None:
        decision, finding = par.authorize_recall(
            _rec(max_privilege=3), _req(caller_privilege=2)
        )
        self.assertEqual(decision, "deny")
        self.assertEqual(finding, "recall-privilege-elevated")

    def test_equal_privilege_allowed(self) -> None:
        decision, finding = par.authorize_recall(
            _rec(max_privilege=2), _req(caller_privilege=2)
        )
        self.assertEqual(decision, "allow")
        self.assertIsNone(finding)

    def test_stale_authority_denied(self) -> None:
        decision, finding = par.authorize_recall(
            _rec(authority_version=3), _req(accepted_authority=2)
        )
        self.assertEqual(decision, "deny")
        self.assertEqual(finding, "recall-stale-authority")

    def test_cross_agent_without_grant_denied(self) -> None:
        decision, finding = par.authorize_recall(
            _rec(owner_agent="analyst-bot", grant=()),
            _req(caller_agent="writer-bot"),
        )
        self.assertEqual(decision, "deny")
        self.assertEqual(finding, "recall-no-grant")

    def test_cross_agent_with_grant_allowed(self) -> None:
        decision, finding = par.authorize_recall(
            _rec(owner_agent="analyst-bot", grant=("writer-bot",)),
            _req(caller_agent="writer-bot"),
        )
        self.assertEqual(decision, "allow")
        self.assertIsNone(finding)

    def test_untrusted_laundered_denied(self) -> None:
        decision, finding = par.authorize_recall(
            _rec(trust="untrusted"), _req(requires_trusted=True)
        )
        self.assertEqual(decision, "deny")
        self.assertEqual(finding, "recall-untrusted-laundered")

    def test_untrusted_allowed_when_not_required(self) -> None:
        decision, finding = par.authorize_recall(
            _rec(trust="untrusted"), _req(requires_trusted=False)
        )
        self.assertEqual(decision, "allow")
        self.assertIsNone(finding)

    def test_tampered_record_denied(self) -> None:
        bad = object.__new__(par.MemoryRecord)
        rec = _rec()
        for field in (
            "record_id", "payload_digest", "writer", "tenant", "owner_agent",
            "trust", "scope", "max_privilege", "grant", "authority_version",
            "seq", "prev_digest",
        ):
            object.__setattr__(bad, field, getattr(rec, field))
        object.__setattr__(bad, "digest", _digest("forged"))
        decision, finding = par.authorize_recall(bad, _req())
        self.assertEqual(decision, "deny")
        self.assertEqual(finding, "recall-unverifiable")

    def test_first_failure_wins(self) -> None:
        # cross-tenant AND privilege elevation: tenant is checked first.
        decision, finding = par.authorize_recall(
            _rec(tenant="acme", max_privilege=9),
            _req(caller_tenant="globex", caller_privilege=1),
        )
        self.assertEqual(decision, "deny")
        self.assertEqual(finding, "recall-cross-tenant")


class FilterCandidatesTests(unittest.TestCase):
    def test_filter_drops_unauthorized(self) -> None:
        records = (
            _rec(record_id="own"),
            _rec(record_id="other-tenant", tenant="globex"),
            _rec(record_id="elevated", max_privilege=9),
        )
        allowed, findings = par.filter_candidates(records, _req())
        self.assertEqual(tuple(r.record_id for r in allowed), ("own",))
        self.assertEqual(len(findings), 2)
        self.assertTrue(all("other-tenant" in f or "elevated" in f for f in findings))

    def test_all_allowed(self) -> None:
        allowed, findings = par.filter_candidates((_rec(), _rec(record_id="r2")), _req())
        self.assertEqual(len(allowed), 2)
        self.assertEqual(findings, ())

    def test_empty_candidates(self) -> None:
        allowed, findings = par.filter_candidates((), _req())
        self.assertEqual(allowed, ())
        self.assertEqual(findings, ())

    def test_never_raises_on_well_formed(self) -> None:
        records = tuple(_rec(record_id=f"r{i}") for i in range(5))
        par.filter_candidates(records, _req())  # must not raise


class VerifyFilterFirstTests(unittest.TestCase):
    def test_attested_true(self) -> None:
        ok, finding = par.verify_filter_first(True)
        self.assertTrue(ok)
        self.assertIsNone(finding)

    def test_false_names_finding(self) -> None:
        ok, finding = par.verify_filter_first(False)
        self.assertFalse(ok)
        self.assertEqual(finding, "recall-identity-filter-missing")

    def test_bad_witness_digest_fails(self) -> None:
        ok, finding = par.verify_filter_first(True, witness_digest="bogus")
        self.assertFalse(ok)
        self.assertEqual(finding, "recall-identity-filter-missing")

    def test_good_witness_digest_ok(self) -> None:
        ok, finding = par.verify_filter_first(True, witness_digest=_digest("w"))
        self.assertTrue(ok)
        self.assertIsNone(finding)


if __name__ == "__main__":
    unittest.main()
