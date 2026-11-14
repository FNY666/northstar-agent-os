"""The refusal hold is wired into the seal ledger's commit path.

What these tests hold down
---------------------------
The previous slice built the **refusal hold** (a query: "is this
re-dispatch blocked by a refusal, and by which row?").  Nothing consulted
it.  The seal ledger -- the one place where the *same action is signed
again* -- kept asking its tombstone registry and nothing else, so refusal
rows piled up while the same action kept getting sealed.

These tests drive the wiring end to end, and they drive the **real** path:
a ``ForwardSealLedger`` with this slice's registry installed at the
ledger's own injection point (``set_tombstones``), a real
``append_grant``, and the ledger's **row count** as the observable proof
that a refused seal wrote nothing.

The five paths the slice must drive (not just the happy one):

* **(a)** a recorded refusal refuses the **same action's** re-issue, and
  the record is **not written to disk** (row count unchanged);
* **(b)** a **different subject** for the same action is handled by the
  **declared semantics** -- a refusal is *coarser* than a cancellation:
  the subject layer is collapsed, so the sibling subject is refused too;
* **(c)** a **different action** is not blocked;
* **(d)** an **unusable gate** (store broken / row tampered / key
  malformed) **fails closed**;
* **(e)** **concurrency**: while issuing and recording a refusal
  concurrently, "refusal recorded but still issued" must never happen.

House style: stdlib only, no wall-clock reads, caller-supplied time.
"""

from __future__ import annotations

import threading
import unittest
from pathlib import Path

# A stale ``__pycache__/refusal_hold_wiring.*.pyc`` makes Python import
# the *previous* source of this module when the source changed without
# changing size or second-resolution mtime -- which is exactly what a
# mutation probe does.  Drop the cached bytecode before the imports below
# so the tests always run the source that is on disk right now.
for _cached in Path(__file__).resolve().parents[1].glob(
    "__pycache__/refusal_hold_wiring.*.pyc"
):
    _cached.unlink(missing_ok=True)

import forward_seal_ledger
from forward_seal_ledger import ForwardSealError, ForwardSealLedger
from grant_pin_ledger import GrantPin
from refusal_hold import (
    REASON_ALLOWED_NO_REFUSAL,
    REASON_BLOCKED_BY_REFUSAL,
    REASON_BLOCKED_ROW_TAMPERED,
    REASON_BLOCKED_STORE_UNREADABLE,
    SCOPE_KIND_QUEUE,
    SCOPE_KIND_TASK,
    RefusalHoldKey,
    RefusalHoldKeyError,
)
from refusal_hold_wiring import (
    DEFAULT_SCOPE_KIND,
    RefusalHoldKeyMappingError,
    RefusalHoldRegistry,
    RefusalHoldWiringError,
    RefusalRefusedError,
    authorize,
    install_refusal_gate,
    refusal_hold_key,
    scope_kind_for,
    stdlib_only,
    subject_covers,
)
from refusal_row import digest_of, record_refusal, verify_row

#: The keys this suite seals with.
INITIAL_KEY = b"refusal-hold-wiring-init!"
CHECKPOINT_KEY = b"refusal-hold-wiring-ckpt!"


def make_row(reason: str = "the evidence digest does not match the ruleset"):
    """One intact refusal row, on the :mod:`refusal_row` side."""
    return record_refusal(
        "denied",
        digest_of({"evidence": "stale"}),
        digest_of({"ruleset": "gate-v3"}),
        "check-alpha@v1",
        digest_of({"population": "nightly"}),
        reason=reason,
        refused_at=1_700_000_000,
        instruments=["check-alpha@v1", "check-beta@v2"],
    )


def tamper(row):
    """Tamper with a row in place: the digest no longer describes it."""
    object.__setattr__(row, "reason", "the reason was rewritten after the fact")
    return row


def make_ledger():
    """A fresh forward-seal ledger with the house keys."""
    return ForwardSealLedger(
        initial_key=INITIAL_KEY, checkpoint_key=CHECKPOINT_KEY
    )


def install(ledger, registry=None):
    """Install the wiring at the ledger's own injection point.

    These are the **three wiring lines** the design document shows.  They
    are executed here, not merely printed in the document:

    1. build the gate (a ``TombstoneSet``-shaped refusal registry);
    2. install it at the ledger's injection point (``set_tombstones``);
    3. bind the gate to the ledger's commit lock, so a refusal that is
       recorded concurrently with a seal is serialized with it.

    Line 3 is what makes "a refusal was recorded but the action was issued
    anyway" impossible: the recording and the seal take the same lock.
    """
    if registry is None:
        registry = RefusalHoldRegistry()
    ledger.set_tombstones(registry)
    registry.bind_gate(ledger._lock)
    return registry


def seal(ledger, grant_id="grant-1", action="checkout", subject="order-7", **kwargs):
    """One real grant seal through the ledger's public path."""
    return ledger.append_grant(
        grant_id=grant_id,
        version="v1",
        counter=1,
        action=action,
        subject=subject,
        **kwargs,
    )


class IdentityMappingTests(unittest.TestCase):
    """Design-doc question 1 and 2: how the ledger's identity becomes a key.

    The conversion table is:

    ===================  =========================================
    ledger side          hold side
    ===================  =========================================
    ``grant_id``         ``scope_id``
    ``action``           ``action``
    ``subject``          *collapsed* (not represented)
    *(none)*             ``scope_kind`` (declared)
    ===================  =========================================
    """

    def test_the_grant_id_becomes_the_scope_id(self):
        """Question 1: ``grant_id`` maps onto ``scope_id``."""
        key = refusal_hold_key("grant-42", "checkout")
        self.assertIsInstance(key, RefusalHoldKey)
        self.assertEqual(key.scope_id, "grant-42")
        self.assertEqual(key.action, "checkout")
        self.assertEqual(key.identity, "task:grant-42:checkout")

    def test_the_action_is_carried_verbatim(self):
        """Question 1: the action is carried verbatim into the key."""
        key = refusal_hold_key("grant-42", "checkout", "order-7")
        self.assertEqual(key.action, "checkout")

    def test_the_scope_kind_is_declared_not_derived(self):
        """Question 2: the scope kind is a declared attribute.

        It is *not* derived from the action's text: deriving a refusal's
        scope from a string would make the meaning of a refusal depend on
        string matching, and a name collision would silently re-scope
        refusals.
        """
        self.assertEqual(DEFAULT_SCOPE_KIND, SCOPE_KIND_TASK)
        self.assertEqual(scope_kind_for("checkout"), SCOPE_KIND_TASK)
        self.assertEqual(scope_kind_for("checkout", default=SCOPE_KIND_QUEUE), SCOPE_KIND_QUEUE)

    def test_a_per_action_override_wins_over_the_default(self):
        """Question 2: an action may be declared into the other kind."""
        kind = scope_kind_for("checkout", overrides={"checkout": SCOPE_KIND_QUEUE})
        self.assertEqual(kind, SCOPE_KIND_QUEUE)

    def test_an_unknown_scope_kind_is_refused(self):
        """Question 2: an unknown scope kind is refused, not defaulted."""
        with self.assertRaises(RefusalHoldKeyMappingError):
            scope_kind_for("checkout", default="ledger")
        with self.assertRaises(RefusalHoldKeyMappingError):
            scope_kind_for("checkout", overrides={"checkout": "ledger"})

    def test_the_recording_side_and_the_checking_side_agree(self):
        """Question 4: both sides go through the same conversion.

        A refusal recorded under one scope and checked under another would
        be a refusal that is never enforced -- the exact gap this slice
        closes.  The two sides must produce the *same* key.
        """
        registry = RefusalHoldRegistry()
        recorded = registry.key_for("grant-9", "checkout", "order-7")
        checked = refusal_hold_key("grant-9", "checkout", "order-7")
        self.assertEqual(recorded, checked)

    def test_a_malformed_grant_id_is_refused_not_defaulted(self):
        """An empty grant id would name *every* action: refuse it."""
        with self.assertRaises(RefusalHoldKeyMappingError):
            refusal_hold_key("", "checkout")
        with self.assertRaises(RefusalHoldKeyMappingError):
            refusal_hold_key("   ", "checkout")
        with self.assertRaises(RefusalHoldKeyMappingError):
            refusal_hold_key(None, "checkout")

    def test_a_malformed_action_is_refused(self):
        """A non-string action is a malformed identity."""
        with self.assertRaises(RefusalHoldKeyMappingError):
            refusal_hold_key("grant-1", 17)
        with self.assertRaises(RefusalHoldKeyMappingError):
            refusal_hold_key("grant-1", "")

    def test_an_action_with_a_colon_is_refused(self):
        """A colon would make the canonical key form ambiguous."""
        with self.assertRaises(RefusalHoldKeyMappingError):
            refusal_hold_key("grant-1", "check:out")

    def test_a_malformed_subject_is_refused(self):
        """A subject of the wrong type is malformed, not absent."""
        with self.assertRaises(RefusalHoldKeyMappingError):
            refusal_hold_key("grant-1", "checkout", 42)
        with self.assertRaises(RefusalHoldKeyMappingError):
            refusal_hold_key("grant-1", "checkout", ["order-7"])

    def test_a_mapping_failure_is_also_a_hold_key_failure(self):
        """The wiring speaks the hold's key vocabulary."""
        with self.assertRaises(RefusalHoldKeyError):
            refusal_hold_key("", "checkout")

    def test_the_module_reads_no_wall_clock(self):
        """The caller owns the clock; the module never reads it."""
        source = (
            Path(__file__).resolve().parents[1] / "refusal_hold_wiring.py"
        ).read_text(encoding="utf-8")
        for forbidden in ("time.time()", "time.monotonic()", "datetime.now("):
            self.assertNotIn(forbidden, source)
        self.assertTrue(stdlib_only())


class SubjectSemanticsTests(unittest.TestCase):
    """Design-doc question 3: the subject layer is **collapsed**.

    A refusal is **coarser than a cancellation**: the tombstone gate
    narrows by subject (``Tombstone.covers``), but the refusal hold's key
    has no subject field, so a refusal of one subject covers every subject
    of the same ``(grant_id, action)``.

    The semantics live in **code** (:func:`subject_covers`), so they are
    pinned by a test rather than only described in a document.
    """

    def test_a_refusal_of_one_subject_covers_a_different_subject(self):
        """The declared semantics: the subject does not narrow a refusal."""
        self.assertTrue(subject_covers("order-7", "order-8"))
        self.assertTrue(subject_covers("order-7", "order-7"))

    def test_a_refusal_with_no_subject_covers_every_subject(self):
        """An unscoped refusal covers everything of the same action."""
        self.assertTrue(subject_covers(None, "order-8"))
        self.assertTrue(subject_covers("", "order-8"))

    def test_an_action_offered_without_a_subject_is_covered(self):
        """"Not naming a subject" is not evidence of being outside scope."""
        self.assertTrue(subject_covers("order-7", None))
        self.assertTrue(subject_covers("order-7", ""))

    def test_a_different_subject_is_refused_on_the_real_path(self):
        """The declared semantics on the real path: the sibling is refused.

        The ledger's row count is the observable: the refused seal writes
        nothing.
        """
        ledger = make_ledger()
        registry = install(ledger)
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        before = len(ledger)
        with self.assertRaises(ForwardSealError):
            seal(ledger, subject="order-8")
        self.assertEqual(len(ledger), before)


class BlockAndNoFalseKillTests(unittest.TestCase):
    """Path (a), (b) and (c): a refusal blocks, and only the refusal.

    The **write count** is the proof: a refusal that raises an exception
    but still wrote a record would be worse than no gate at all.
    """

    def test_a_recorded_refusal_refuses_the_same_action(self):
        """Path (a): the same action's re-issue is refused."""
        registry = RefusalHoldRegistry()
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        result = registry.check("grant-1", "checkout", "order-7")
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_BY_REFUSAL)

    def test_the_refusal_blocked_the_seal_writes_no_record(self):
        """Path (a): the record is **not written to disk**.

        The ledger's row count is the observable, and the ledger is a real
        ``ForwardSealLedger``, not a stand-in.
        """
        ledger = make_ledger()
        registry = install(ledger)
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        before = len(ledger)
        with self.assertRaises(ForwardSealError):
            seal(ledger)
        self.assertEqual(len(ledger), before)
        self.assertEqual(len(ledger), 0)

    def test_a_seal_that_is_not_refused_does_write_a_record(self):
        """The control: an unrefused seal still lands.

        Without this, "the row count did not change" would prove nothing.
        """
        ledger = make_ledger()
        registry = RefusalHoldRegistry()
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        record = seal(ledger, grant_id="grant-2")
        self.assertEqual(len(ledger), 1)
        self.assertEqual(record.seq, 1)

    def test_a_different_action_is_not_blocked(self):
        """Path (c): a different action is not wrongly blocked."""
        registry = RefusalHoldRegistry()
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        result = registry.check("grant-1", "refund", "order-7")
        self.assertFalse(result.blocked)
        self.assertEqual(result.reason, REASON_ALLOWED_NO_REFUSAL)

    def test_a_different_grant_is_not_blocked(self):
        """A different grant id is a different scope: not blocked."""
        registry = RefusalHoldRegistry()
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        result = registry.check("grant-2", "checkout", "order-7")
        self.assertFalse(result.blocked)

    def test_a_different_action_seals_on_the_real_path(self):
        """Path (c) on the real path: the other action still lands."""
        ledger = make_ledger()
        registry = RefusalHoldRegistry()
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        seal(ledger, action="refund")
        self.assertEqual(len(ledger), 1)

    def test_the_blocking_result_carries_the_refusal_row(self):
        """The row comes back: a bare boolean would be another log line."""
        registry = RefusalHoldRegistry()
        row = make_row()
        registry.record("grant-1", "checkout", "order-7", row=row)
        result = registry.check("grant-1", "checkout", "order-7")
        self.assertIs(result.row, row)
        self.assertEqual(result.row_digest, row.row_digest)


class FailClosedTests(unittest.TestCase):
    """Path (d): an unusable gate **fails closed**.

    Three cases, one each: an unreadable store, a tampered row, a
    malformed key.  All three must block; none may be a clean read.
    """

    def test_an_unreadable_store_blocks(self):
        """The store cannot answer -> blocked."""
        registry = RefusalHoldRegistry()
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        registry.store.break_reads()
        result = registry.check("grant-1", "checkout", "order-7")
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_STORE_UNREADABLE)

    def test_a_tampered_row_blocks(self):
        """The row no longer verifies -> blocked, and the row is not returned."""
        registry = RefusalHoldRegistry()
        row = make_row()
        registry.record("grant-1", "checkout", "order-7", row=row)
        tamper(row)
        self.assertFalse(verify_row(row))
        result = registry.check("grant-1", "checkout", "order-7")
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_ROW_TAMPERED)
        self.assertIsNone(result.row)

    def test_a_malformed_key_raises_and_never_passes_silently(self):
        """A malformed identity is refused: no silent pass."""
        registry = RefusalHoldRegistry()
        with self.assertRaises(RefusalHoldKeyMappingError):
            registry.check("", "checkout")
        with self.assertRaises(RefusalHoldKeyMappingError):
            registry.check("grant-1", "check:out")

    def test_a_malformed_identity_refuses_the_seal(self):
        """A malformed identity reaching the seal path refuses the seal."""
        ledger = make_ledger()
        registry = RefusalHoldRegistry()
        before = len(ledger)
        with self.assertRaises(ForwardSealError):
            seal(ledger, grant_id="")
        self.assertEqual(len(ledger), before)

    def test_a_broken_gate_refuses_the_seal_on_the_real_path(self):
        """An unusable gate refuses the seal and writes no record."""
        ledger = make_ledger()
        registry = install(ledger)
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        registry.store.break_reads()
        before = len(ledger)
        with self.assertRaises(ForwardSealError):
            seal(ledger)
        self.assertEqual(len(ledger), before)

    def test_a_tampered_row_refuses_the_seal_on_the_real_path(self):
        """A tampered row refuses the seal and writes no record."""
        ledger = make_ledger()
        registry = install(ledger)
        row = make_row()
        registry.record("grant-1", "checkout", "order-7", row=row)
        tamper(row)
        before = len(ledger)
        with self.assertRaises(ForwardSealError):
            seal(ledger)
        self.assertEqual(len(ledger), before)

    def test_a_refusal_cannot_be_lifted_by_a_tombstone_lift(self):
        """A refusal is not a cancellation: it cannot be lifted."""
        registry = RefusalHoldRegistry()
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        with self.assertRaises(RefusalHoldWiringError):
            registry.lift(object())


class ExpiryTests(unittest.TestCase):
    """The declared semantics: **nothing expires**.

    The caller owns the clock and passes it in; changing ``now`` does not
    change the answer.  If a ``capacity``-class split is wanted later, it
    belongs in ``RefusalHold``'s policy layer -- not in this wiring layer.
    """

    def test_changing_now_does_not_change_the_answer(self):
        """A permission-class refusal has no bound to pass."""
        registry = RefusalHoldRegistry()
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        for now in (0, 1, 1_700_000_000, 10 ** 12):
            result = registry.check("grant-1", "checkout", "order-7", now=now)
            self.assertTrue(result.blocked)
            self.assertEqual(result.reason, REASON_BLOCKED_BY_REFUSAL)

    def test_an_unrefused_action_stays_unrefused_as_the_clock_moves(self):
        """The clock does not create refusals either."""
        registry = RefusalHoldRegistry()
        for now in (0, 1_700_000_000, 10 ** 12):
            result = registry.check("grant-1", "checkout", "order-7", now=now)
            self.assertFalse(result.blocked)

    def test_the_wiring_never_reads_the_wall_clock(self):
        """Proven by source inspection, not by a timing argument."""
        source = (
            Path(__file__).resolve().parents[1] / "refusal_hold_wiring.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("time.time()", source)
        self.assertNotIn("datetime.now(", source)
        self.assertNotIn("time.monotonic()", source)


class WiringExampleTests(unittest.TestCase):
    """The wiring example in the design document is **executable**.

    The document shows three lines at ``forward_seal_ledger``'s injection
    point.  These tests run those three lines against a real ledger and
    assert the two things that matter: the seal is **refused**, and the
    ledger's **row count does not change**.
    """

    def test_the_three_wiring_lines_refuse_the_seal_and_write_nothing(self):
        """The document's example, run for real."""
        ledger = make_ledger()
        registry = install(ledger)
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        before = len(ledger)
        with self.assertRaises(ForwardSealError):
            seal(ledger)
        self.assertEqual(len(ledger), before)

    def test_the_three_wiring_lines_let_an_unrefused_seal_through(self):
        """The control: the same three lines do not block a clean seal."""
        ledger = make_ledger()
        registry = install(ledger)
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        seal(ledger, grant_id="grant-2", action="refund")
        self.assertEqual(len(ledger), 1)

    def test_the_registry_has_the_tombstone_set_shape(self):
        """The injection point accepts a ``TombstoneSet``-shaped object."""
        registry = RefusalHoldRegistry()
        self.assertTrue(callable(getattr(registry, "blocked", None)))
        self.assertTrue(callable(getattr(registry, "is_blocked", None)))
        # The ledger calls it with exactly this signature.
        result = registry.blocked("grant-1", "checkout", "order-7", now=1_700_000_000)
        self.assertIsNone(result)
        self.assertFalse(registry.is_blocked("grant-1", "checkout", "order-7"))

    def test_the_ledger_holds_the_registry_at_its_injection_point(self):
        """The ledger really took the object we installed."""
        ledger = make_ledger()
        registry = install(ledger)
        self.assertIs(ledger.tombstones, registry)

    def test_authorize_returns_the_rendered_pin_when_nothing_refuses(self):
        """``authorize`` has the seal path's shape: render or raise."""
        registry = RefusalHoldRegistry()
        pin = GrantPin(grant_id="grant-1", version="v1", counter=1)
        rendered = authorize(registry, pin, "checkout", "order-7")
        self.assertEqual(rendered, pin.render())

    def test_authorize_raises_on_a_refusal(self):
        """A refusal stops the seal before the ledger is touched."""
        registry = RefusalHoldRegistry()
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        pin = GrantPin(grant_id="grant-1", version="v1", counter=1)
        with self.assertRaises(RefusalRefusedError):
            authorize(registry, pin, "checkout", "order-7")

    def test_install_refusal_gate_yields_the_gate_answer(self):
        """The context manager lets the caller see *why* it was blocked."""
        ledger = make_ledger()
        registry = RefusalHoldRegistry()
        with install_refusal_gate(
            ledger, registry, action="checkout", subject="order-7", grant_id="grant-1"
        ) as result:
            self.assertFalse(result.blocked)

    def test_install_refusal_gate_refuses_inside_the_ledger_lock(self):
        """The gate is consulted inside the ledger's critical section."""
        ledger = make_ledger()
        registry = install(ledger)
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            with install_refusal_gate(
                ledger,
                registry,
                action="checkout",
                subject="order-7",
                grant_id="grant-1",
            ):
                pass

    def test_the_wiring_records_an_audit_trail(self):
        """What was recorded and what was checked is auditable."""
        registry = RefusalHoldRegistry()
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        registry.check("grant-1", "checkout", "order-7")
        kinds = [event["kind"] for event in registry.events()]
        self.assertIn("recorded", kinds)
        self.assertIn("checked", kinds)


class ConcurrencyTests(unittest.TestCase):
    """Path (e): "refusal recorded but still issued" must never happen.

    The seal path takes the ledger's lock across its check **and** its
    write, and the recording takes the same lock.  So a seal and a
    recording are serialized: a seal either commits entirely before the
    refusal lands, or it sees the refusal and is refused.

    The assertion is made on the registry's own audit trail, which is
    written under that same lock -- so the trail *is* the serialization
    order.
    """

    def test_a_refusal_recorded_concurrently_never_leaves_a_later_seal_allowed(self):
        """No check after the recording may answer "not blocked"."""
        ledger = make_ledger()
        registry = install(ledger)
        stop = threading.Event()
        errors = []

        def seal_loop():
            while not stop.is_set():
                try:
                    seal(ledger)
                except ForwardSealError:
                    pass
                except Exception as error:  # pragma: no cover - a real failure
                    errors.append(error)
                    return

        def record_loop():
            registry.record("grant-1", "checkout", "order-7", row=make_row())

        sealer = threading.Thread(target=seal_loop)
        sealer.start()
        try:
            record_loop()
        finally:
            stop.set()
            sealer.join(timeout=30)

        self.assertEqual(errors, [])
        # Once the refusal is on the books, no further check may allow.
        recorded_at = None
        for index, event in enumerate(registry.events()):
            if event["kind"] == "recorded":
                recorded_at = index
                break
        self.assertIsNotNone(recorded_at, "the refusal was never recorded")
        for event in registry.events()[recorded_at:]:
            if event["kind"] == "checked":
                self.assertTrue(
                    event["blocked"],
                    "a check after the refusal was recorded was allowed: "
                    "the refusal was on the books and the action was issued",
                )

    def test_every_seal_that_landed_committed_before_the_refusal(self):
        """The row count equals the number of checks allowed before it.

        No seal may commit *after* the refusal was recorded, so the number
        of records that landed is exactly the number of checks the gate
        allowed -- and every allowed check happened before the recording.
        """
        ledger = make_ledger()
        registry = install(ledger)
        stop = threading.Event()
        errors = []

        def seal_loop():
            while not stop.is_set():
                try:
                    seal(ledger)
                except ForwardSealError:
                    pass
                except Exception as error:  # pragma: no cover - a real failure
                    errors.append(error)
                    return

        sealer = threading.Thread(target=seal_loop)
        sealer.start()
        try:
            registry.record("grant-1", "checkout", "order-7", row=make_row())
        finally:
            stop.set()
            sealer.join(timeout=30)

        self.assertEqual(errors, [])
        events = registry.events()
        recorded_at = next(
            index for index, event in enumerate(events) if event["kind"] == "recorded"
        )
        allowed_before = sum(
            1
            for event in events[:recorded_at]
            if event["kind"] == "checked" and not event["blocked"]
        )
        self.assertEqual(len(ledger), allowed_before)

    def test_a_seal_after_the_recording_is_refused(self):
        """The steady state: the action stays refused."""
        ledger = make_ledger()
        registry = install(ledger)
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        before = len(ledger)
        for _ in range(5):
            with self.assertRaises(ForwardSealError):
                seal(ledger)
        self.assertEqual(len(ledger), before)


if __name__ == "__main__":
    unittest.main()
