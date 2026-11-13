"""Tests for the refusal row (``refusal_row``).

The rule under test: **a refusal is a row, not a log line.**  A refusal
that leaves no record is indistinguishable from a check that never ran,
so the "no" itself has to be auditable: a verdict, the digest of the
evidence it rests on, the digest of the rules that were applied, the key
of the verifier that produced it, and the digest of the population it was
taken over.

The source's own rule -- "two instruments or none" -- is the second
half: a refusal that one instrument produced alone is an opinion, so it
must be *declared* (``single_instrument=True``) and marked on the row; a
refusal with no instrument at all is an absence, and absence is refused.

The tests drive real paths through the module: a full refusal is
recorded, re-verified, tampered with and re-verified again, and the
fail-closed paths are exercised one by one.
"""
import dataclasses
import unittest

from refusal_row import (
    DIGEST_PREFIX,
    MARKER_SINGLE_INSTRUMENT,
    RefusalRow,
    RefusalRowError,
    digest_of,
    record_refusal,
    row_errors,
    verify_row,
)

EVIDENCE = digest_of({"evidence": "stale snapshot"})
RULESET = digest_of({"ruleset": "gate-v3"})
POPULATION = digest_of({"population": "nightly-regression"})


def two_instrument_row(**overrides):
    """A refusal resting on two distinct instruments."""
    kwargs = dict(
        verdict="denied",
        evidence_hash=EVIDENCE,
        ruleset_hash=RULESET,
        verifier_key="check-alpha@v1",
        population_digest=POPULATION,
        reason="the evidence digest does not match the ruleset",
        refused_at=1_700_000_000,
        instruments=["check-alpha@v1", "check-beta@v2"],
    )
    kwargs.update(overrides)
    return record_refusal(**kwargs)


class RecordRefusalTests(unittest.TestCase):
    """Recording a refusal as an auditable row."""

    def test_two_instruments_record_a_row_that_verifies(self):
        row = two_instrument_row()
        self.assertTrue(verify_row(row))
        self.assertEqual(row.verdict, "denied")
        self.assertEqual(row.evidence_hash, EVIDENCE)
        self.assertEqual(row.ruleset_hash, RULESET)
        self.assertEqual(row.verifier_key, "check-alpha@v1")
        self.assertEqual(row.population_digest, POPULATION)
        self.assertEqual(row.instrument_count, 2)
        self.assertEqual(row.marker, "")
        self.assertEqual(row_errors(row), ())

    def test_the_refusal_is_a_row_not_a_log_line(self):
        """The row carries its own evidence -- it is readable without the log."""
        row = two_instrument_row()
        payload = row.as_dict()
        for field in (
            "verdict",
            "evidence_hash",
            "ruleset_hash",
            "verifier_key",
            "population_digest",
            "refused_at",
            "reason",
        ):
            self.assertIn(field, payload)
            self.assertNotEqual(payload[field], "")
        self.assertEqual(payload["schema"], "northstar.refusal-row.v1")
        self.assertTrue(payload["row_digest"].startswith(DIGEST_PREFIX))
        # The row is self-describing: its digest can be recomputed from it.
        self.assertEqual(payload["row_digest"], row.content_digest())

    def test_refused_at_is_caller_supplied_and_not_wall_clock(self):
        row = two_instrument_row(refused_at=42)
        self.assertEqual(row.refused_at, 42)
        with self.assertRaises(RefusalRowError):
            two_instrument_row(refused_at="now")

    def test_duplicate_instrument_keys_count_as_one(self):
        """Two *different* instruments are required -- the same key twice is one."""
        with self.assertRaises(RefusalRowError):
            two_instrument_row(
                instruments=["check-alpha@v1", "check-alpha@v1"],
                verifier_key="check-alpha@v1",
            )
        # Declared as the single instrument it really is, the row records one.
        row = two_instrument_row(
            instruments=["check-alpha@v1", "check-alpha@v1"],
            verifier_key="check-alpha@v1",
            single_instrument=True,
        )
        self.assertEqual(row.instrument_count, 1)
        self.assertEqual(row.marker, MARKER_SINGLE_INSTRUMENT)
        self.assertTrue(verify_row(row))


class FailClosedTests(unittest.TestCase):
    """A refusal missing any evidence field is not a refusal row."""

    def test_missing_population_digest_is_refused(self):
        """The source names this field as the missing one."""
        with self.assertRaises(RefusalRowError) as ctx:
            record_refusal(
                "denied",
                EVIDENCE,
                RULESET,
                "check-alpha@v1",
                "",
                reason="no population digest",
                instruments=["check-alpha@v1", "check-beta@v2"],
            )
        self.assertIn("population_digest", str(ctx.exception))

    def test_missing_evidence_hash_is_refused(self):
        for missing in ("", None, "   "):
            with self.assertRaises(RefusalRowError) as ctx:
                record_refusal(
                    "denied",
                    missing,
                    RULESET,
                    "check-alpha@v1",
                    POPULATION,
                    reason="no evidence",
                    instruments=["check-alpha@v1", "check-beta@v2"],
                )
            self.assertIn("evidence_hash", str(ctx.exception))

    def test_missing_ruleset_hash_is_refused(self):
        with self.assertRaises(RefusalRowError) as ctx:
            record_refusal(
                "denied",
                EVIDENCE,
                "",
                "check-alpha@v1",
                POPULATION,
                reason="no ruleset",
                instruments=["check-alpha@v1", "check-beta@v2"],
            )
        self.assertIn("ruleset_hash", str(ctx.exception))

    def test_missing_verifier_key_is_refused(self):
        with self.assertRaises(RefusalRowError) as ctx:
            record_refusal(
                "denied",
                EVIDENCE,
                RULESET,
                "",
                POPULATION,
                reason="no verifier",
                instruments=["check-alpha@v1", "check-beta@v2"],
            )
        self.assertIn("verifier_key", str(ctx.exception))

    def test_missing_verdict_is_refused(self):
        with self.assertRaises(RefusalRowError):
            record_refusal(
                "",
                EVIDENCE,
                RULESET,
                "check-alpha@v1",
                POPULATION,
                reason="no verdict",
                instruments=["check-alpha@v1", "check-beta@v2"],
            )

    def test_malformed_digest_is_refused(self):
        """A digest that is not ``sha256:`` + 64 lowercase hex is not a digest."""
        for malformed in (
            "sha256:nothex",
            "sha256:" + "0" * 63,
            "sha256:" + "0" * 65,
            "sha256:" + "A" * 64,
            "md5:" + "0" * 64,
            "0" * 64,
            EVIDENCE + "extra",
        ):
            with self.assertRaises(RefusalRowError):
                record_refusal(
                    "denied",
                    malformed,
                    RULESET,
                    "check-alpha@v1",
                    POPULATION,
                    reason="malformed evidence digest",
                    instruments=["check-alpha@v1", "check-beta@v2"],
                )

    def test_malformed_verifier_key_is_refused(self):
        for malformed in ("", "no-at-sign", "@v1", "subject@", "Subject@v1"):
            with self.assertRaises(RefusalRowError):
                record_refusal(
                    "denied",
                    EVIDENCE,
                    RULESET,
                    malformed,
                    POPULATION,
                    reason="malformed verifier key",
                    instruments=["check-alpha@v1", "check-beta@v2"],
                )

    def test_verifier_key_must_be_one_of_the_instruments(self):
        with self.assertRaises(RefusalRowError):
            record_refusal(
                "denied",
                EVIDENCE,
                RULESET,
                "check-gamma@v3",
                POPULATION,
                reason="key not among instruments",
                instruments=["check-alpha@v1", "check-beta@v2"],
            )


class TwoInstrumentRuleTests(unittest.TestCase):
    """"Two instruments or none"."""

    def test_zero_instruments_is_refused(self):
        """A refusal with no instrument is an absence, not a refusal."""
        with self.assertRaises(RefusalRowError) as ctx:
            record_refusal(
                "denied",
                EVIDENCE,
                RULESET,
                "check-alpha@v1",
                POPULATION,
                reason="no instruments at all",
                instruments=[],
            )
        self.assertIn("two instruments or none", str(ctx.exception))

    def test_single_instrument_without_declaration_is_refused(self):
        with self.assertRaises(RefusalRowError) as ctx:
            record_refusal(
                "denied",
                EVIDENCE,
                RULESET,
                "check-alpha@v1",
                POPULATION,
                reason="only one verifier",
                instruments=["check-alpha@v1"],
            )
        self.assertIn("single_instrument", str(ctx.exception))

    def test_single_instrument_with_declaration_is_recorded_and_marked(self):
        row = record_refusal(
            "denied",
            EVIDENCE,
            RULESET,
            "check-alpha@v1",
            POPULATION,
            reason="the second verifier was unreachable at the boundary",
            refused_at=1_700_000_001,
            instruments=["check-alpha@v1"],
            single_instrument=True,
        )
        self.assertTrue(verify_row(row))
        self.assertEqual(row.marker, MARKER_SINGLE_INSTRUMENT)
        self.assertEqual(row.instrument_count, 1)
        self.assertEqual(row.as_dict()["marker"], MARKER_SINGLE_INSTRUMENT)

    def test_single_instrument_declaration_still_needs_a_reason(self):
        with self.assertRaises(RefusalRowError) as ctx:
            record_refusal(
                "denied",
                EVIDENCE,
                RULESET,
                "check-alpha@v1",
                POPULATION,
                reason="",
                instruments=["check-alpha@v1"],
                single_instrument=True,
            )
        self.assertIn("reason", str(ctx.exception))

    def test_declaring_single_instrument_with_two_is_refused(self):
        """The marker must not contradict the row's own content."""
        with self.assertRaises(RefusalRowError):
            record_refusal(
                "denied",
                EVIDENCE,
                RULESET,
                "check-alpha@v1",
                POPULATION,
                reason="contradiction",
                instruments=["check-alpha@v1", "check-beta@v2"],
                single_instrument=True,
            )

    def test_default_instruments_is_the_single_verifier_key(self):
        """No instruments given means one -- which must be declared."""
        with self.assertRaises(RefusalRowError):
            record_refusal(
                "denied", EVIDENCE, RULESET, "check-alpha@v1", POPULATION, reason="x"
            )
        row = record_refusal(
            "denied",
            EVIDENCE,
            RULESET,
            "check-alpha@v1",
            POPULATION,
            reason="only one verifier was available",
            single_instrument=True,
        )
        self.assertEqual(row.instruments, ("check-alpha@v1",))


class ImmutabilityTests(unittest.TestCase):
    """A refusal row is append-only: it cannot be edited after creation."""

    def test_the_row_is_frozen(self):
        row = two_instrument_row()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            row.verdict = "allowed"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            row.evidence_hash = EVIDENCE
        with self.assertRaises(dataclasses.FrozenInstanceError):
            row.population_digest = POPULATION
        with self.assertRaises(dataclasses.FrozenInstanceError):
            row.refused_at = 0

    def test_the_row_cannot_be_replaced_by_a_dataclass_update(self):
        """``dataclasses.replace`` cannot rebuild a row with different fields."""
        row = two_instrument_row()
        with self.assertRaises((RefusalRowError, dataclasses.FrozenInstanceError)):
            dataclasses.replace(row, verdict="allowed")

    def test_there_is_no_update_interface(self):
        """To change a refusal you record another row."""
        import refusal_row

        self.assertFalse(hasattr(refusal_row, "update_refusal"))
        self.assertFalse(hasattr(refusal_row, "amend_refusal"))
        self.assertFalse(hasattr(refusal_row, "replace_refusal"))


class TamperTests(unittest.TestCase):
    """A tampered row is not a refusal row."""

    @staticmethod
    def forge(row, **changes):
        """Tamper with a row the way a forger would: behind the frozen check.

        ``object.__setattr__`` bypasses ``frozen=True``, which is exactly
        the attack the row's own digest is there to catch.
        """
        for name, value in changes.items():
            object.__setattr__(row, name, value)
        return row

    def test_tampered_evidence_hash_fails_verification(self):
        row = two_instrument_row()
        forged = self.forge(row, evidence_hash=digest_of({"evidence": "something else"}))
        self.assertFalse(verify_row(forged))
        self.assertTrue(any("tampered" in err for err in row_errors(forged)))

    def test_tampered_row_digest_fails_verification(self):
        row = two_instrument_row()
        forged = self.forge(row, row_digest=digest_of("nonsense"))
        self.assertFalse(verify_row(forged))
        self.assertIn(
            "row_digest does not match the row content (tampered)", row_errors(forged)
        )

    def test_tampered_population_digest_fails_verification(self):
        row = two_instrument_row()
        forged = self.forge(row, population_digest=digest_of({"population": "other"}))
        self.assertFalse(verify_row(forged))

    def test_tampered_instrument_count_fails_verification(self):
        """Dropping the second instrument to make a weak row look strong."""
        row = two_instrument_row()
        forged = self.forge(row, instruments=("check-alpha@v1",))
        self.assertFalse(verify_row(forged))

    def test_tampered_verdict_fails_verification(self):
        """Rewriting "denied" into "allowed" is the forgery that matters."""
        row = two_instrument_row()
        forged = self.forge(row, verdict="allowed")
        self.assertFalse(verify_row(forged))

    def test_verify_row_rejects_a_non_row(self):
        self.assertFalse(verify_row("not a row"))
        self.assertFalse(verify_row(None))
        self.assertFalse(verify_row({"verdict": "denied"}))
