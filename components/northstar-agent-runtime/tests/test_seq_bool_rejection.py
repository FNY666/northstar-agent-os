"""Six seq guards that accepted a bool, and the repo's own convention.

WHY THIS FILE EXISTS (measured 2026-11-26)
-------------------------------------------
``bool`` is a subclass of ``int`` in Python, so ``isinstance(True, int)``
is ``True``.  A seq guard written as

    if not isinstance(seq, int) or seq < 0:
        raise ...

therefore accepts ``True`` and ``False``.  The repo does NOT use that
shape: **1266** of the runtime's seq-ish int guards spell the bool half
out explicitly, as

    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:

SIX modules were the exception, and each of them accepted a bool seq:

    monitor_channel_probes     MonitorRecord(seq=True)
    privilege_at_recall_probes build_record(seq=True)
    evidence_compaction_probes build_item(..., seq=True)
    fraud_detector             fraud_detector_audit_event(seq=True)
    tax_calculator             add_rate / calculate / exempt(seq=True)
    mfa_manager                enroll(..., seq=True)

The aliasing is not cosmetic.  ``True == 1`` and ``False == 0``, so a
bool seq is indistinguishable from the int seq it aliases: a
``TaxRate`` added at ``seq=True`` reports ``added_seq == 1``, and the
ledger's "this rate was applied at seq N" claim becomes ambiguous
between ``N`` and ``N-1``.

THE FIX
-------
One line per site, and the raise is the site's OWN error class -- the
suite asserts the exception TYPE, so a fix that raised the wrong class
would be caught.

THE CONTROL
-----------
Every rejection case is paired with an acceptance case on the SAME
site: a plain int seq must still be accepted.  A guard that refused
everything would pass every rejection test.

THE NON-VACUITY CONTROL
-----------------------
A test that cannot fail proves nothing.  ``test_the_replanted_defect
_fails_the_suite`` RE-PLANTS the original defect -- the guard with the
bool half removed -- in a COPY of the runtime, and asserts that the
suite then FAILS.  If that assertion ever passes, the suite has stopped
measuring the defect.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

RUNTIME = pathlib.Path(__file__).resolve().parent.parent


def _load(name: str):
    """Load one module by file path (the house loader)."""
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


monitor_channel_probes = _load("monitor_channel_probes")
privilege_at_recall_probes = _load("privilege_at_recall_probes")
evidence_compaction_probes = _load("evidence_compaction_probes")
fraud_detector = _load("fraud_detector")
tax_calculator = _load("tax_calculator")
mfa_manager = _load("mfa_manager")

DIGEST = "sha256:" + "00" * 32


def _monitor_record(seq):
    """Build a monitor record with a correct digest pin, at any seq."""
    return monitor_channel_probes.build_record(
        seq=seq,
        direction="egress",
        channel="ch",
        payload_digest=DIGEST,
        origin="host",
    )


def _privilege_record(seq):
    return privilege_at_recall_probes.build_record(
        record_id="r",
        payload_digest=DIGEST,
        writer="w",
        tenant="t",
        owner_agent="o",
        trust=list(privilege_at_recall_probes.TRUST_ORIGINS)[0],
        seq=seq,
    )


class SeqBoolRejectionTests(unittest.TestCase):
    """A bool seq is refused, with the site's OWN error class."""

    def test_monitor_channel_probes_refuses_a_bool_seq(self) -> None:
        for seq in (True, False):
            with self.subTest(seq=seq):
                with self.assertRaises(ValueError):
                    _monitor_record(seq)

    def test_privilege_at_recall_probes_refuses_a_bool_seq(self) -> None:
        for seq in (True, False):
            with self.subTest(seq=seq):
                with self.assertRaises(ValueError):
                    _privilege_record(seq)

    def test_evidence_compaction_probes_refuses_a_bool_seq(self) -> None:
        kind = evidence_compaction_probes.ITEM_KINDS[0]
        for seq in (True, False):
            with self.subTest(seq=seq):
                with self.assertRaises(ValueError):
                    evidence_compaction_probes.build_item(
                        kind, "content", DIGEST, seq
                    )

    def test_fraud_detector_refuses_a_bool_seq(self) -> None:
        for seq in (True, False):
            with self.subTest(seq=seq):
                with self.assertRaises(fraud_detector.FraudError):
                    fraud_detector.fraud_detector_audit_event("scored", seq=seq)

    def test_tax_calculator_refuses_a_bool_seq(self) -> None:
        calculator = tax_calculator.TaxCalculator()
        for seq in (True, False):
            with self.subTest(seq=seq):
                with self.assertRaises(tax_calculator.TaxConfigError):
                    calculator.add_rate("US", "vat", 100, seq)
        calculator = tax_calculator.TaxCalculator()
        with self.assertRaises(tax_calculator.TaxConfigError):
            calculator.calculate(11900, "US", True)
        calculator = tax_calculator.TaxCalculator()
        with self.assertRaises(tax_calculator.TaxConfigError):
            calculator.exempt("E1", "US", True)

    def test_mfa_manager_refuses_a_bool_seq(self) -> None:
        manager_cls = [
            value
            for value in vars(mfa_manager).values()
            if isinstance(value, type) and "_check_seq" in value.__dict__
        ][0]
        for seq in (True, False):
            with self.subTest(seq=seq):
                manager = manager_cls()
                with self.assertRaises(TypeError):
                    manager.enroll("alice", "totp", seq)


class SeqBoolAcceptanceTests(unittest.TestCase):
    """THE CONTROL: a plain int seq is still accepted, everywhere."""

    def test_a_plain_int_seq_is_still_accepted(self) -> None:
        self.assertEqual(_monitor_record(1).seq, 1)
        self.assertEqual(_privilege_record(1).seq, 1)
        kind = evidence_compaction_probes.ITEM_KINDS[0]
        self.assertEqual(
            evidence_compaction_probes.build_item(kind, "content", DIGEST, 1).seq, 1
        )
        row = fraud_detector.fraud_detector_audit_event("scored", seq=1)
        self.assertEqual(row["seq"], 1)
        calculator = tax_calculator.TaxCalculator()
        self.assertEqual(calculator.add_rate("US", "vat", 100, 1).added_seq, 1)
        manager_cls = [
            value
            for value in vars(mfa_manager).values()
            if isinstance(value, type) and "_check_seq" in value.__dict__
        ][0]
        manager = manager_cls()
        manager.enroll("alice", "totp", 1)


class SeqBoolSiblingGuardTests(unittest.TestCase):
    """The SIBLING int guards in the same six modules.

    **A GUARD ON ONE PATH LEAVES THE OTHERS OPEN.**  The six seq
    guards were the ones a sweep for "a seq parameter" found, but the
    same six modules guard OTHER int fields the same way, and those
    guards accepted a bool too:

    * `privilege_at_recall_probes`: `max_privilege`,
      `authority_version`, `caller_privilege`, `accepted_authority`
    * `tax_calculator`: `rate_bps`, `net_cents`
    * `mfa_manager`: `count` (the backup-code count), `sign_count`
      (the webauthn verification counter)

    `tax_calculator` shows why this is not cosmetic: a rate registered
    at `rate_bps=True` is a rate of ONE BASIS POINT, and a quote
    computed at `net_cents=True` is a quote of ONE CENT -- both of
    which then compare equal to the int they alias.
    """

    def test_privilege_at_recall_probes_refuses_a_bool_privilege(self) -> None:
        trust = list(privilege_at_recall_probes.TRUST_ORIGINS)[0]
        for field in ("max_privilege", "authority_version"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    privilege_at_recall_probes.build_record(
                        record_id="r",
                        payload_digest=DIGEST,
                        writer="w",
                        tenant="t",
                        owner_agent="o",
                        trust=trust,
                        seq=1,
                        **{field: True},
                    )

    def test_privilege_at_recall_probes_refuses_a_bool_authority(self) -> None:
        for field in ("caller_privilege", "accepted_authority"):
            with self.subTest(field=field):
                kwargs = {
                    "caller_agent": "a",
                    "caller_tenant": "t",
                    "purpose": "p",
                    "requires_trusted": False,
                    "caller_privilege": 0,
                    "accepted_authority": 1,
                }
                kwargs[field] = True
                with self.assertRaises(ValueError):
                    privilege_at_recall_probes.build_request(**kwargs)

    def test_tax_calculator_refuses_a_bool_amount(self) -> None:
        calculator = tax_calculator.TaxCalculator()
        with self.assertRaises(tax_calculator.TaxConfigError):
            calculator.add_rate("US", "vat", True, 1)
        calculator = tax_calculator.TaxCalculator()
        calculator.add_rate("US", "vat", 100, 1)
        with self.assertRaises(tax_calculator.TaxConfigError):
            calculator.calculate(True, "US", 1)

    def test_mfa_manager_refuses_a_bool_count(self) -> None:
        manager_cls = [
            value
            for value in vars(mfa_manager).values()
            if isinstance(value, type) and "_check_seq" in value.__dict__
        ][0]
        manager = manager_cls()
        with self.assertRaises(ValueError):
            manager.backup("alice", 1, True)

    def test_mfa_manager_refuses_a_bool_sign_count(self) -> None:
        """THE OBSERVABLE DIFFERS HERE, and the test has to follow it.

        ``mfa_manager.verify`` returns a ``VerifyResult`` for
        malformed input -- it does NOT raise.  So the observable for
        the webauthn signature-counter guard is the RESULT's
        ``reason`` field, not an exception:

            sign_count=True  ->  reason='malformed'
            sign_count=1     ->  reason='bad-signature'

        A test that asserted "an exception was raised" would fail
        against the FIXED module; a test that asserted only
        "valid is False" would pass under the mutant too, because the
        mutant also ends up not-valid -- for the WRONG reason.
        """
        manager_cls = [
            value
            for value in vars(mfa_manager).values()
            if isinstance(value, type) and "_check_seq" in value.__dict__
        ][0]
        manager = manager_cls()
        record = manager.enroll("alice", "webauthn", 1)
        malformed = manager.verify(
            "alice",
            "webauthn",
            2,
            cred_id=record.cred_id,
            challenge=b"challenge",
            response=b"response",
            sign_count=True,
            rp_id="northstar.local",
        )
        self.assertFalse(malformed.valid)
        self.assertEqual(malformed.reason, "malformed")
        # THE CONTROL: the same call with a plain int is NOT malformed.
        good = manager.verify(
            "alice",
            "webauthn",
            3,
            cred_id=record.cred_id,
            challenge=b"challenge",
            response=b"response",
            sign_count=1,
            rp_id="northstar.local",
        )
        self.assertNotEqual(good.reason, "malformed")

    def test_a_plain_int_sibling_is_still_accepted(self) -> None:
        """THE CONTROL for the sibling guards."""
        trust = list(privilege_at_recall_probes.TRUST_ORIGINS)[0]
        record = privilege_at_recall_probes.build_record(
            record_id="r",
            payload_digest=DIGEST,
            writer="w",
            tenant="t",
            owner_agent="o",
            trust=trust,
            seq=1,
            max_privilege=3,
            authority_version=2,
        )
        self.assertEqual(record.max_privilege, 3)
        self.assertEqual(record.authority_version, 2)
        calculator = tax_calculator.TaxCalculator()
        rate = calculator.add_rate("US", "vat", 100, 1)
        self.assertEqual(rate.rate_bps, 100)
        quote = calculator.calculate(11900, "US", 1)
        self.assertEqual(quote.net_cents, 11900)
        manager_cls = [
            value
            for value in vars(mfa_manager).values()
            if isinstance(value, type) and "_check_seq" in value.__dict__
        ][0]
        manager = manager_cls()
        manager.backup("alice", 1, 3)


class SeqBoolNonVacuityTests(unittest.TestCase):
    """THE NON-VACUITY CONTROL: re-plant the defect; the suite must fail.

    The mutation is planted in a COPY of the runtime, never in the
    working tree: a probe that mutates the tree it is measuring
    contaminates every later measurement.
    """

    #: (file, the fixed line, the line with the bool half removed)
    SITES = (
        (
            "monitor_channel_probes.py",
            "        if isinstance(self.seq, bool) or not isinstance(self.seq, int) or self.seq < 0:",
            "        if not isinstance(self.seq, int) or self.seq < 0:",
        ),
        (
            "fraud_detector.py",
            "    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:",
            "    if not isinstance(seq, int) or seq < 0:",
        ),
        (
            "evidence_compaction_probes.py",
            "    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:",
            "    if not isinstance(seq, int) or seq < 0:",
        ),
        (
            "tax_calculator.py",
            "        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:",
            "        if not isinstance(seq, int) or seq < 0:",
        ),
        (
            "mfa_manager.py",
            "        if isinstance(seq, bool) or not isinstance(seq, int):",
            "        if not isinstance(seq, int):",
        ),
        (
            "privilege_at_recall_probes.py",
            "        if isinstance(self.seq, bool) or not isinstance(self.seq, int) or self.seq < 0:",
            "        if not isinstance(self.seq, int) or self.seq < 0:",
        ),
        # the SIBLING int guards in the same modules
        (
            "privilege_at_recall_probes.py",
            "        if isinstance(self.max_privilege, bool) or not isinstance(self.max_privilege, int) or self.max_privilege < 0:",
            "        if not isinstance(self.max_privilege, int) or self.max_privilege < 0:",
        ),
        (
            "privilege_at_recall_probes.py",
            "        if isinstance(self.authority_version, bool) or not isinstance(self.authority_version, int) or self.authority_version < 0:",
            "        if not isinstance(self.authority_version, int) or self.authority_version < 0:",
        ),
        (
            "privilege_at_recall_probes.py",
            "    if isinstance(self.caller_privilege, bool) or not isinstance(self.caller_privilege, int) or self.caller_privilege < 0:",
            "    if not isinstance(self.caller_privilege, int) or self.caller_privilege < 0:",
        ),
        (
            "privilege_at_recall_probes.py",
            "    if isinstance(self.accepted_authority, bool) or not isinstance(self.accepted_authority, int) or self.accepted_authority < 0:",
            "    if not isinstance(self.accepted_authority, int) or self.accepted_authority < 0:",
        ),
        (
            "tax_calculator.py",
            "        if isinstance(rate_bps, bool) or not isinstance(rate_bps, int) or rate_bps < 0 or rate_bps > 10000:",
            "        if not isinstance(rate_bps, int) or rate_bps < 0 or rate_bps > 10000:",
        ),
        (
            "tax_calculator.py",
            "        if isinstance(net_cents, bool) or not isinstance(net_cents, int) or net_cents < 0:",
            "        if not isinstance(net_cents, int) or net_cents < 0:",
        ),
        (
            "mfa_manager.py",
            "        if isinstance(count, bool) or not isinstance(count, int) or count < 1 or count > 64:",
            "        if not isinstance(count, int) or count < 1 or count > 64:",
        ),
        (
            "mfa_manager.py",
            "                or isinstance(sign_count, bool) or not isinstance(sign_count, int)",
            "                or not isinstance(sign_count, int)",
        ),
    )

    def test_the_replanted_defect_fails_the_suite(self) -> None:
        # ONE copy for all sixteen sites: the runtime is copied once,
        # each site is re-planted in turn, and the file is restored
        # after each one.  Copying per site would leave sixteen stale
        # trees behind and is what filled /tmp on the first attempt.
        with tempfile.TemporaryDirectory() as elsewhere:
            work = pathlib.Path(elsewhere) / "runtime"
            shutil.copytree(
                RUNTIME,
                work,
                ignore=shutil.ignore_patterns("__pycache__", "build"),
            )
            for filename, fixed, defective in self.SITES:
                with self.subTest(module=filename):
                    target = work / filename
                    original = target.read_text()
                    self.assertIn(
                        fixed,
                        original,
                        f"{filename}: the fixed guard line is not present, so "
                        f"this control would measure nothing",
                    )
                    # DROP THE CACHED BYTECODE.  The re-plant replaces
                    # " or " with " and " -- the SAME LENGTH -- and the
                    # two sites are planted within the same wall-clock
                    # second, so Python's .pyc validation (source mtime
                    # in whole seconds + source size) would REUSE the
                    # previous run's bytecode and the mutant would
                    # never be loaded.  The control would then report
                    # "the defect passed" when the mutant was never
                    # executed at all.
                    self._drop_bytecode(work, filename)
                    target.write_text(original.replace(fixed, defective, 1))
                    try:
                        result = subprocess.run(
                            [
                                sys.executable,
                                "-m",
                                "pytest",
                                "-q",
                                "-p",
                                "no:cacheprovider",
                                "tests/test_seq_bool_rejection.py",
                                "-k",
                                "not replanted",
                            ],
                            cwd=str(work),
                            capture_output=True,
                            text=True,
                            env={**os.environ, "PYTHONPATH": f"{work}:{work / 'tests'}"},
                            timeout=300,
                        )
                    finally:
                        target.write_text(original)
                        self._drop_bytecode(work, filename)
                    self.assertNotEqual(
                        result.returncode,
                        0,
                        f"{filename}: the re-planted defect PASSED the suite -- "
                        f"the suite is no longer measuring the defect",
                    )

    @staticmethod
    def _drop_bytecode(work: pathlib.Path, filename: str) -> None:
        """Remove the cached .pyc of ``filename``, if any."""
        cache = work / "__pycache__"
        if not cache.is_dir():
            return
        stem = filename[:-3] if filename.endswith(".py") else filename
        for cached in cache.glob(f"{stem}.*.pyc"):
            try:
                cached.unlink()
            except OSError:
                pass


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
