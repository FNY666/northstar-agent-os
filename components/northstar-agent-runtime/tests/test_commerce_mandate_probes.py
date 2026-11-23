"""Tests for commerce_mandate_probes.py."""

import unittest

import commerce_mandate_probes as cmp


def _digest(suffix: str) -> str:
    return "sha256:" + suffix * 64


_ISSUERS = {"user-bank": "sha256:" + "k" * 64}


def _mandate(**over):
    kw = {
        "mandate_id": "m-001",
        "payer_id": "user-1",
        "authorized_agent": "agent-7",
        "payee_id": "merchant-a",
        "amount_minor": 10000,
        "currency": "USD",
        "task_digest": _digest("t"),
        "issuer_id": "user-bank",
        "expires_iso": "2027-01-01T00:00:00Z",
    }
    kw.update(over)
    return cmp.build_mandate(**kw)


def _pay_kwargs(mandate=None, **over):
    kw = {
        "amount_minor": 10000,
        "currency": "USD",
        "payee_id": "merchant-a",
        "task_digest": _digest("t"),
        "ledger": cmp.MandateLedger(),
        "now_iso": "2026-10-07T00:00:00Z",
        "issuer_registry": _ISSUERS,
    }
    kw.update(over)
    return kw


class CorpusShapeTests(unittest.TestCase):
    def test_attack_and_benign_counts(self):
        self.assertEqual(len(cmp.COMMERCE_MANDATE_PROBES), 10)
        self.assertEqual(len(cmp.COMMERCE_MANDATE_BENIGN), 3)

    def test_required_keys(self):
        for probe in (*cmp.COMMERCE_MANDATE_PROBES,
                      *cmp.COMMERCE_MANDATE_BENIGN):
            for key in ("probe", "family", "attack",
                        "gate_interaction", "expected", "reason"):
                self.assertIn(key, probe, probe.get("probe"))

    def test_unique_names(self):
        names = [p["probe"] for p in (*cmp.COMMERCE_MANDATE_PROBES,
                                     *cmp.COMMERCE_MANDATE_BENIGN)]
        self.assertEqual(len(names), len(set(names)))

    def test_deny_side_keywords_on_all_attacks(self):
        for probe in cmp.COMMERCE_MANDATE_PROBES:
            text = probe["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in cmp.DENY_SIDE_KEYWORDS),
                f"{probe['probe']} gate_interaction names no deny-side keyword",
            )

    def test_per_family_counts(self):
        # probes_in_family includes benign controls (sibling convention)
        self.assertEqual(len(cmp.probes_in_family("forged-mandate")), 5)  # 4 + 1
        self.assertEqual(len(cmp.probes_in_family("mandate-replay")), 4)  # 3 + 1
        self.assertEqual(len(cmp.probes_in_family("amount-switching")), 4)  # 3 + 1

    def test_expected_outcomes(self):
        outcomes = cmp.expected_outcomes()
        for name in cmp.attack_probe_names():
            self.assertEqual(outcomes[name], "deny")
        for name in cmp.benign_probe_names():
            self.assertEqual(outcomes[name], "allow")

    def test_probe_by_name(self):
        probe = cmp.probe_by_name("switch-amount-raised")
        self.assertEqual(probe["family"], "amount-switching")
        with self.assertRaises(KeyError):
            cmp.probe_by_name("no-such-probe")

    def test_main_runs(self):
        cmp.main()  # must not raise


class MandateRecordTests(unittest.TestCase):
    def test_build_and_verify_round_trip(self):
        mandate = _mandate()
        self.assertTrue(cmp.verify_mandate(mandate))
        self.assertTrue(mandate.digest.startswith("sha256:"))

    def test_tampered_amount_fails(self):
        mandate = _mandate()
        tampered = cmp.CommerceMandate(
            mandate_id=mandate.mandate_id,
            payer_id=mandate.payer_id,
            authorized_agent=mandate.authorized_agent,
            payee_id=mandate.payee_id,
            amount_minor=95000,  # edited, digest not recomputed
            currency=mandate.currency,
            task_digest=mandate.task_digest,
            issuer_id=mandate.issuer_id,
            expires_iso=mandate.expires_iso,
            digest=mandate.digest,
        )
        self.assertFalse(cmp.verify_mandate(tampered))

    def test_bad_inputs_rejected(self):
        with self.assertRaises(ValueError):
            _mandate(mandate_id="")
        with self.assertRaises(ValueError):
            _mandate(currency="usd")  # must be uppercase ISO-4217
        with self.assertRaises(ValueError):
            _mandate(currency="USDD")
        with self.assertRaises(ValueError):
            _mandate(amount_minor=-1)
        with self.assertRaises(ValueError):
            _mandate(amount_minor=10.5)  # floats never appear
        with self.assertRaises(ValueError):
            _mandate(task_digest="not-a-digest")

    def test_verify_rejects_non_mandate(self):
        self.assertFalse(cmp.verify_mandate("nope"))
        self.assertFalse(cmp.verify_mandate(None))


class LedgerTests(unittest.TestCase):
    def test_consume_once(self):
        ledger = cmp.MandateLedger()
        digest = _digest("x")
        self.assertTrue(ledger.consume(digest))
        self.assertTrue(ledger.is_consumed(digest))
        self.assertFalse(ledger.consume(digest))  # replay refused
        self.assertEqual(ledger.consumed_count(), 1)


class GateTests(unittest.TestCase):
    def test_honest_payment_authorized_and_consumed(self):
        mandate = _mandate()
        ledger = cmp.MandateLedger()
        decision, findings = cmp.authorize_payment(
            mandate, **_pay_kwargs(ledger=ledger))
        self.assertEqual(decision, cmp.DECISION_AUTHORIZED)
        self.assertEqual(findings, ())
        self.assertTrue(ledger.is_consumed(mandate.digest))

    def test_denied_payment_never_consumes(self):
        mandate = _mandate()
        ledger = cmp.MandateLedger()
        decision, findings = cmp.authorize_payment(
            mandate, **_pay_kwargs(ledger=ledger, amount_minor=95000))
        self.assertEqual(decision, cmp.DECISION_DENIED)
        self.assertFalse(ledger.is_consumed(mandate.digest))

    def test_double_spend_replayed(self):
        mandate = _mandate()
        ledger = cmp.MandateLedger()
        cmp.authorize_payment(mandate, **_pay_kwargs(ledger=ledger))
        decision, findings = cmp.authorize_payment(
            mandate, **_pay_kwargs(ledger=ledger))
        self.assertEqual(decision, cmp.DECISION_DENIED)
        self.assertIn(cmp.FINDING_REPLAYED, findings)

    def test_amount_raised_denied(self):
        mandate = _mandate()
        decision, findings = cmp.authorize_payment(
            mandate, **_pay_kwargs(amount_minor=95000))
        self.assertEqual(decision, cmp.DECISION_DENIED)
        self.assertIn(cmp.FINDING_AMOUNT_SWITCHED, findings)

    def test_amount_lowered_denied(self):
        mandate = _mandate()
        decision, findings = cmp.authorize_payment(
            mandate, **_pay_kwargs(amount_minor=1))
        self.assertEqual(decision, cmp.DECISION_DENIED)
        self.assertIn(cmp.FINDING_AMOUNT_SWITCHED, findings)

    def test_currency_switched_denied(self):
        mandate = _mandate()
        decision, findings = cmp.authorize_payment(
            mandate, **_pay_kwargs(currency="EUR"))
        self.assertEqual(decision, cmp.DECISION_DENIED)
        self.assertIn(cmp.FINDING_CURRENCY_SWITCHED, findings)

    def test_payee_switched_denied(self):
        mandate = _mandate()
        decision, findings = cmp.authorize_payment(
            mandate, **_pay_kwargs(payee_id="merchant-b"))
        self.assertEqual(decision, cmp.DECISION_DENIED)
        self.assertIn(cmp.FINDING_PAYEE_SWITCHED, findings)

    def test_cross_task_denied(self):
        mandate = _mandate()
        decision, findings = cmp.authorize_payment(
            mandate, **_pay_kwargs(task_digest=_digest("z")))
        self.assertEqual(decision, cmp.DECISION_DENIED)
        self.assertIn(cmp.FINDING_TASK_SCOPE_MISMATCH, findings)

    def test_expired_mandate_denied(self):
        mandate = _mandate(expires_iso="2020-01-01T00:00:00Z")
        decision, findings = cmp.authorize_payment(
            mandate, **_pay_kwargs())
        self.assertEqual(decision, cmp.DECISION_DENIED)
        self.assertIn(cmp.FINDING_EXPIRED, findings)

    def test_expiry_uncheckable_denied(self):
        mandate = _mandate()
        decision, findings = cmp.authorize_payment(
            mandate, **_pay_kwargs(now_iso=""))
        self.assertEqual(decision, cmp.DECISION_DENIED)
        self.assertIn(cmp.FINDING_EXPIRY_UNCHECKABLE, findings)

    def test_unknown_issuer_forged(self):
        mandate = _mandate(issuer_id="agent-self-key")
        decision, findings = cmp.authorize_payment(
            mandate, **_pay_kwargs())
        self.assertEqual(decision, cmp.DECISION_DENIED)
        self.assertIn(cmp.FINDING_FORGED, findings)

    def test_tampered_mandate_unverifiable(self):
        mandate = _mandate()
        tampered = cmp.CommerceMandate(
            mandate_id=mandate.mandate_id,
            payer_id=mandate.payer_id,
            authorized_agent=mandate.authorized_agent,
            payee_id=mandate.payee_id,
            amount_minor=95000,
            currency=mandate.currency,
            task_digest=mandate.task_digest,
            issuer_id=mandate.issuer_id,
            expires_iso=mandate.expires_iso,
            digest=mandate.digest,
        )
        decision, findings = cmp.authorize_payment(
            tampered, **_pay_kwargs())
        self.assertEqual(decision, cmp.DECISION_DENIED)
        self.assertIn(cmp.FINDING_UNVERIFIABLE, findings)

    def test_non_mandate_denied(self):
        decision, findings = cmp.authorize_payment(
            "not-a-mandate", **_pay_kwargs())
        self.assertEqual(decision, cmp.DECISION_DENIED)
        self.assertIn(cmp.FINDING_UNVERIFIABLE, findings)

    def test_no_expiry_mandate_authorized(self):
        mandate = _mandate(expires_iso="")
        decision, findings = cmp.authorize_payment(
            mandate, **_pay_kwargs())
        self.assertEqual(decision, cmp.DECISION_AUTHORIZED)
        self.assertEqual(findings, ())

    def test_renewal_is_not_replay(self):
        first = _mandate(mandate_id="m-001")
        second = _mandate(mandate_id="m-002")
        self.assertNotEqual(first.digest, second.digest)
        ledger = cmp.MandateLedger()
        d1, _ = cmp.authorize_payment(first, **_pay_kwargs(ledger=ledger))
        d2, _ = cmp.authorize_payment(second, **_pay_kwargs(ledger=ledger))
        self.assertEqual(d1, cmp.DECISION_AUTHORIZED)
        self.assertEqual(d2, cmp.DECISION_AUTHORIZED)
        self.assertEqual(ledger.consumed_count(), 2)

    def test_split_mandates_compose(self):
        task = _digest("t")
        m1 = _mandate(mandate_id="m-001", amount_minor=6000,
                      task_digest=task)
        m2 = _mandate(mandate_id="m-002", amount_minor=4000,
                      task_digest=task)
        ledger = cmp.MandateLedger()
        d1, f1 = cmp.authorize_payment(
            m1, **_pay_kwargs(ledger=ledger, amount_minor=6000))
        d2, f2 = cmp.authorize_payment(
            m2, **_pay_kwargs(ledger=ledger, amount_minor=4000))
        self.assertEqual((d1, f1), (cmp.DECISION_AUTHORIZED, ()))
        self.assertEqual((d2, f2), (cmp.DECISION_AUTHORIZED, ()))

    def test_findings_vocabulary_fixed(self):
        self.assertEqual(len(cmp.FINDINGS), 9)
        self.assertIn(cmp.FINDING_AMOUNT_SWITCHED, cmp.FINDINGS)


if __name__ == "__main__":
    unittest.main()
