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

import forward_seal_ledger as _FSL
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
    queue_hold_key,
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


class WiringGuardTests(unittest.TestCase):
    """The wiring's own guards, driven one half at a time.

    Nine planted faults survived the suite that drives the *wiring*:

    * ``gt@640`` -- the audit trail's trim bound.  This one is
      **EQUIVALENT**, and is proved so differentially rather than
      asserted (see
      ``test_the_trim_rule_is_equivalent_under_the_planted_fault``);
    * ``and@759`` / ``and@764`` -- the two halves of
      ``_current_grant_id``'s "is this a usable grant id?" check;
    * ``retF@801`` / ``retF@804`` -- the two "this import is not
      allowed, so the module is not stdlib-only" returns;
    * ``eq@831`` / ``eq@835`` / ``eq@842`` / ``eq@848`` -- the module's
      own ``main()`` self-check asserts and its ``__main__`` guard.

    The techniques are the repository's own (see
    ``tests/test_retry_config.py``): run the self-check for real, and
    drive one half of a conjunction at a time by patching the
    collaborator the guard reads.
    """

    # -- gt@640: the audit trail's trim bound ----------------------------

    def test_the_trim_rule_is_equivalent_under_the_planted_fault(self):
        """`gt@640`: a DIFFERENTIAL proof that the fault is EQUIVALENT.

        ``_record_event`` keeps the trail bounded::

            if len(self._events) > MAX_WIRING_EVENTS:
                del self._events[: len(self._events) - MAX_WIRING_EVENTS]

        The planted fault is ``>`` -> ``>=``.  This test proves the two
        spellings are **behaviourally identical** by running them side
        by side on the REAL module: the module's source is copied twice
        into a temporary directory -- once unchanged, once with that one
        comparison mutated -- both copies are imported as separate
        modules, and both registries are driven through the same
        sequence of recordings and checks.

        The two trails are then compared event by event.  If the fault
        were killable, the two copies would diverge at the boundary and
        the comparison would find it.  It does not, and the reason is
        structural: at ``len(self._events) == MAX_WIRING_EVENTS`` the
        original does not trim, and the delete the mutant would run
        there is ``del events[:0]`` -- which removes nothing.  So the
        two spellings leave the trail in the same state at every length.

        This test exists so the next person does not spend a round
        looking for a killer that cannot exist.  The negative control
        (``test_the_differential_harness_would_catch_an_observable_mutation``)
        proves the harness is not vacuous.
        """
        import pathlib
        import tempfile

        import refusal_hold_wiring

        source = pathlib.Path(refusal_hold_wiring.__file__).read_text(
            encoding="utf-8"
        )
        # Both spellings of the comparison are built from the source, so
        # the proof holds whichever one the module on disk carries --
        # including the mutated one.  That is what makes this an
        # equivalence proof rather than a textual check.
        strict_source = self._trim_comparison_spelling(source, ">")
        loose_source = self._trim_comparison_spelling(source, ">=")
        self.assertNotEqual(
            strict_source,
            loose_source,
            "the two spellings of the trim must differ in the source",
        )

        with tempfile.TemporaryDirectory() as directory:
            strict = self._load_copy(
                pathlib.Path(directory), "wiring_strict", strict_source
            )
            loose = self._load_copy(
                pathlib.Path(directory), "wiring_loose", loose_source
            )

            strict_trail = self._drive_trail(strict)
            loose_trail = self._drive_trail(loose)

        self.assertEqual(
            strict_trail,
            loose_trail,
            "the '>' and '>=' spellings of the trim must produce the same "
            "trail -- the planted fault is EQUIVALENT",
        )

    def _trim_comparison_spelling(self, source, operator):
        """Return ``source`` with the trim comparison spelled ``operator``.

        The comparison is located by the AST rather than by an exact
        source string, so the rewrite still lands if the surrounding
        text is reworded -- a fingerprint on the exact wording would
        make this test a textual check dressed up as a behavioural one.

        Both ``>`` and ``>=`` are accepted when locating the
        comparison, so the rewrite works on the original module and on
        the mutated one alike.
        """
        import ast

        tree = ast.parse(source)
        candidates = []
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and isinstance(node.ops[0], (ast.Gt, ast.GtE))
            ):
                continue
            left = node.left
            if not (
                isinstance(left, ast.Call)
                and isinstance(left.func, ast.Name)
                and left.func.id == "len"
                and len(left.args) == 1
                and isinstance(left.args[0], ast.Attribute)
                and left.args[0].attr == "_events"
            ):
                continue
            candidates.append(node.lineno)
        self.assertEqual(
            len(candidates),
            1,
            "the trim comparison must be found exactly once in the module",
        )
        lines = source.splitlines(keepends=True)
        index = candidates[0] - 1
        line = lines[index]
        # Rewrite the comparison to the requested spelling, whichever
        # one it currently carries.  The rewrite is done on the
        # comparison's own operator, so it is idempotent: asking for
        # ">=" when the source already says ">=" leaves it alone, and
        # asking for ">" never turns ">=" into ">==".
        if operator == ">":
            rewritten = line.replace(">=", ">", 1)
        else:
            rewritten = line.replace(">=", ">", 1).replace(">", ">=", 1)
        mutated = lines[:]
        mutated[index] = rewritten
        return "".join(mutated)

    def _load_copy(self, directory, name, source):
        """Write ``source`` to a file and import it under ``name``."""
        import importlib.util
        import sys

        path = directory / f"{name}.py"
        path.write_text(source, encoding="utf-8")
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    def _drive_trail(self, module):
        """Drive a registry through the trim boundary and return its trail.

        The trail is driven across the boundary on purpose: the events
        are recorded first (so the trail grows one event at a time) and
        then checked, and the whole trail is compared afterwards.
        """
        registry = module.RefusalHoldRegistry()
        row = make_row()
        registry.record("grant-1", "checkout", "order-7", row=row)
        cap = module.MAX_WIRING_EVENTS
        for _ in range(cap + 3):
            registry.check("grant-1", "checkout", "order-7")
            registry.check("grant-2", "refund", "order-9")
        return registry.events()

    def test_the_differential_harness_would_catch_an_observable_mutation(self):
        """`gt@640`: the negative control for the equivalence proof.

        An equivalence claim is only worth as much as the harness that
        produced it.  This test plants a mutation of the same trim rule
        that IS observable -- the delete removes one event too many at
        the boundary -- and asserts that the differential harness
        **does** report a difference for it.

        So the "no difference" result of
        ``test_the_trim_rule_is_equivalent_under_the_planted_fault`` is
        a real measurement and not a harness that cannot fail.
        """
        import pathlib
        import tempfile

        import refusal_hold_wiring

        source = pathlib.Path(refusal_hold_wiring.__file__).read_text(
            encoding="utf-8"
        )
        observable = self._observable_trim_mutation(source)
        self.assertNotEqual(
            observable,
            source,
            "the observable mutation must actually change the module source",
        )

        with tempfile.TemporaryDirectory() as directory:
            original = self._load_copy(
                pathlib.Path(directory), "wiring_control_original", source
            )
            mutant = self._load_copy(
                pathlib.Path(directory), "wiring_control_mutant", observable
            )
            original_trail = self._drive_trail(original)
            mutant_trail = self._drive_trail(mutant)

        self.assertNotEqual(
            original_trail,
            mutant_trail,
            "the harness must detect a mutation that really changes the trail",
        )

    def _observable_trim_mutation(self, source):
        """Return ``source`` with the trim's delete made one event short.

        The mutation is the same *rule* the equivalence proof exercises,
        changed so that it IS observable: at the boundary the delete now
        removes one event too many, so the two spellings of the
        comparison diverge and the harness can see it.
        """
        import ast

        tree = ast.parse(source)
        candidates = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Delete) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not (
                isinstance(target, ast.Subscript)
                and isinstance(target.slice, ast.Slice)
            ):
                continue
            candidates.append(node.lineno)
        self.assertEqual(
            len(candidates),
            1,
            "the trim's delete must be found exactly once in the module",
        )
        lines = source.splitlines(keepends=True)
        index = candidates[0] - 1
        line = lines[index]
        rewritten = line.replace(
            "- MAX_WIRING_EVENTS]", "- MAX_WIRING_EVENTS - 1]", 1
        )
        self.assertNotEqual(
            rewritten,
            line,
            "the observable mutation must actually change the delete",
        )
        mutated = lines[:]
        mutated[index] = rewritten
        return "".join(mutated)

    def test_the_audit_trail_is_trimmed_at_the_bound(self):
        """`gt@640`: the boundary, and why the fault is equivalent.

        ``_record_event`` keeps the trail bounded::

            if len(self._events) > MAX_WIRING_EVENTS:
                del self._events[: len(self._events) - MAX_WIRING_EVENTS]

        The planted fault is ``>`` -> ``>=``.  It is an **EQUIVALENT
        mutant**, and this is the proof rather than an assertion of one:

        * at ``len(self._events) == MAX_WIRING_EVENTS`` (the boundary),
          the original does NOT trim -- and the delete it would run is
          ``del events[:0]``, which removes nothing either.  So the two
          spellings leave the trail in the SAME state;
        * at every other length the two conditions agree (``>`` and
          ``>=`` differ only at equality), and the same delete runs.

        ``test_the_trim_rule_is_equivalent_under_the_planted_fault``
        proves this differentially, on the real module.  This test pins
        the bound itself -- at every length above the cap the trail is
        trimmed back to exactly ``MAX_WIRING_EVENTS``, and it never
        grows past the cap -- so the *behaviour* the mutant would have
        preserved is what the suite holds down.
        """
        import refusal_hold_wiring

        cap = refusal_hold_wiring.MAX_WIRING_EVENTS
        registry = RefusalHoldRegistry()
        row = make_row()
        registry.record("grant-1", "checkout", "order-7", row=row)
        for index in range(cap + 5):
            registry.check("grant-1", "checkout", "order-7")
            self.assertLessEqual(
                len(registry.events()),
                cap,
                "the audit trail must never grow past its bound",
            )
        self.assertEqual(len(registry.events()), cap)

    def test_the_audit_trail_holds_every_event_up_to_the_bound(self):
        """`gt@640`: the other side of the boundary.

        Below the cap nothing is trimmed: every recorded event is still
        in the trail.  The mutant would not change this either (the two
        conditions agree strictly below the cap), but pinning it makes
        the boundary behaviour visible rather than assumed.
        """
        import refusal_hold_wiring

        cap = refusal_hold_wiring.MAX_WIRING_EVENTS
        registry = RefusalHoldRegistry()
        row = make_row()
        registry.record("grant-1", "checkout", "order-7", row=row)
        for index in range(cap - 1):
            registry.check("grant-1", "checkout", "order-7")
        self.assertEqual(len(registry.events()), cap)

    # -- and@759 / and@764: the grant-id guards --------------------------

    def test_a_non_string_grant_id_attribute_is_not_a_grant_id(self):
        """`and@759`: the first half of the ledger-attribute guard.

        ``if isinstance(value, str) and value:`` -- the second half
        ("is it non-empty?") never refuses a **non-string**, so only the
        ``isinstance`` half does.  Under the fault (``and`` -> ``or``)
        a non-empty non-string is accepted as a grant id.

        So the killer must supply a value that is **not a string but is
        truthy**: an ``int`` passes ``value`` and fails
        ``isinstance(value, str)``.
        """
        from refusal_hold_wiring import _current_grant_id

        class Ledger:
            _current_grant_id = 7

        self.assertIsNone(_current_grant_id(Ledger()))

    def test_a_non_string_pin_grant_id_is_not_a_grant_id(self):
        """`and@764`: the first half of the pin guard.

        The same guard, one level down: the pin's ``grant_id`` is
        checked with ``isinstance(grant_id, str) and grant_id``.  The
        killer supplies a truthy non-string.
        """
        from refusal_hold_wiring import _current_grant_id

        class Pin:
            grant_id = 7

        class Ledger:
            _current_pin = Pin()

        self.assertIsNone(_current_grant_id(Ledger()))

    def test_an_empty_string_grant_id_is_not_a_grant_id(self):
        """`and@759` / `and@764`: the second half of the guards.

        The other half of each conjunction is the emptiness check, and
        it is the half that refuses an **empty string**.  Under the
        fault (``and`` -> ``or``) an empty string is accepted as a
        grant id, because ``or`` short-circuits on the empty-string
        falsiness and never reaches the emptiness refusal.

        The killer supplies the empty string, which is a string (so the
        first half holds) and empty (so the second half is the one that
        must refuse).
        """
        from refusal_hold_wiring import _current_grant_id

        class Ledger:
            _current_grant_id = ""

        self.assertIsNone(_current_grant_id(Ledger()))

    def test_an_empty_pin_grant_id_is_not_a_grant_id(self):
        """`and@764`: the second half of the pin guard."""
        from refusal_hold_wiring import _current_grant_id

        class Pin:
            grant_id = ""

        class Ledger:
            _current_pin = Pin()

        self.assertIsNone(_current_grant_id(Ledger()))

    def test_a_usable_grant_id_is_still_named(self):
        """`and@759` / `and@764`: the control.

        A guard that refused every grant id would be as broken as one
        that accepted every value, so the positive case is pinned too.
        """
        from refusal_hold_wiring import _current_grant_id

        class Ledger:
            _current_grant_id = "grant-1"

        self.assertEqual(_current_grant_id(Ledger()), "grant-1")

    # -- retF@801 / retF@804: the stdlib-only guard ----------------------

    def test_a_disallowed_plain_import_makes_the_module_not_stdlib_only(self):
        """`retF@801`: the ``import`` half of the allow-list check.

        ``stdlib_only()`` walks the module's own AST and returns False
        for an import outside the allow-list.  Under the fault
        (``return False`` -> ``return True``) a module that imports a
        third-party package would still be declared stdlib-only.

        The killer writes the module's own source plus a disallowed
        ``import`` into a temporary file, points ``stdlib_only()`` at
        it, and asserts the answer is False.
        """
        import pathlib
        import tempfile

        import refusal_hold_wiring

        self._assert_not_stdlib_only_with(
            refusal_hold_wiring, "import requests\n", "import"
        )

    def test_a_disallowed_from_import_makes_the_module_not_stdlib_only(self):
        """`retF@804`: the ``from ... import ...`` half.

        The same guard, the other branch of the AST walk.  Under the
        fault (``return False`` -> ``return True``) a module that pulls
        in a third-party package through a ``from``-import would still
        be declared stdlib-only.
        """
        import refusal_hold_wiring

        self._assert_not_stdlib_only_with(
            refusal_hold_wiring, "from requests import get\n", "from"
        )

    def _assert_not_stdlib_only_with(self, module, extra_source, label):
        """Assert ``stdlib_only()`` rejects ``extra_source``.

        The module's own source is copied and the extra import appended,
        so the AST walk sees exactly one disallowed import and nothing
        else changes.
        """
        import pathlib
        import tempfile

        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        original = module.__file__
        with tempfile.TemporaryDirectory() as directory:
            candidate = pathlib.Path(directory) / "wiring_under_test.py"
            candidate.write_text(source + "\n" + extra_source, encoding="utf-8")
            module.__file__ = str(candidate)
            try:
                self.assertFalse(
                    module.stdlib_only(),
                    f"a module with a disallowed {label} is not stdlib-only",
                )
            finally:
                module.__file__ = original

    def test_the_module_itself_is_stdlib_only(self):
        """`retF@801` / `retF@804`: the control.

        The real module IS stdlib-only, so the guard's True answer is
        pinned as well -- a guard that returned False for everything
        would also be broken.
        """
        import refusal_hold_wiring

        self.assertTrue(refusal_hold_wiring.stdlib_only())

    # -- eq@831 / eq@835 / eq@842 / eq@848: the self-check ---------------

    def test_the_self_check_passes_on_the_real_code(self):
        """`eq@831` / `eq@835` / `eq@842`: the self-check's own asserts.

        The self-check states the CORRECT semantics -- the recorded
        refusal refuses the seal with the ``blocked_by_refusal`` reason,
        a different action is allowed with the ``allowed_no_refusal``
        reason, and a broken store blocks with the
        ``blocked_store_unreadable`` reason.  So under ``==`` -> ``!=``
        one of the asserts asks the opposite question and the correct
        behaviour FAILS it: the self-check raises instead of printing
        "ok", which is exactly the no-op self-check the fault creates.
        """
        import io
        from contextlib import redirect_stdout

        import refusal_hold_wiring

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            refusal_hold_wiring.main()
        self.assertIn("refusal-hold-wiring self-check: ok", buffer.getvalue())

    def test_running_the_module_as_a_script_runs_the_self_check(self):
        """`eq@848`: the ``__main__`` guard.

        ``if __name__ == "__main__":`` becomes ``!=`` under the fault,
        and then the self-check runs on EVERY import and NEVER runs when
        the module is run as a script -- which is how it is used.
        """
        import io
        from contextlib import redirect_stdout

        import runpy

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            runpy.run_module("refusal_hold_wiring", run_name="__main__")
        self.assertIn("refusal-hold-wiring self-check: ok", buffer.getvalue())


class TwoGateFamiliesTests(unittest.TestCase):
    """The ledger has **two** gate families and only **one** slot.

    The cancellation tombstone and the refusal hold are both
    ``TombstoneSet``-shaped objects, and both are installed at the
    ledger's single injection point (``set_tombstones``).  The second
    install **replaced** the first, so a host that wired the refusal
    gate after the cancellation gate silently **lost** the cancellation
    block: the ledger sealed the very action the tombstone covered.

    Measured 2026-11-21 on this branch:

        ledger.set_tombstones(tombstone_set)   # cancellation gate
        ledger.set_tombstones(refusal_registry)  # refusal gate
        ledger.append_grant(grant_id="grant-1", action="dispatch")
        -> len(ledger) == 1     # the tombstone block was LOST

    The fix is structural: the ledger keeps **both** families, consults
    **both**, and a second install of a *different* family refuses
    instead of silently replacing the first.
    """

    def _tombstone_set(self, grant_id="grant-1", action="dispatch", subject=""):
        from cancellation_tombstone import Tombstone, TombstoneSet

        return TombstoneSet(
            [
                Tombstone(
                    grant_id=grant_id,
                    action=action,
                    subject=subject,
                    declarer="ops",
                    declarer_channel="ops-channel",
                )
            ]
        )

    def test_the_second_install_does_not_drop_the_first_gate(self):
        """The fail-open itself: both gates are consulted."""
        ledger = make_ledger()
        tombstones = self._tombstone_set()
        registry = RefusalHoldRegistry()
        ledger.set_tombstones(tombstones)
        ledger.set_tombstones(registry)
        before = len(ledger)
        with self.assertRaises(ForwardSealError):
            seal(ledger, grant_id="grant-1", action="dispatch", subject="")
        self.assertEqual(len(ledger), before)

    def test_the_refusal_gate_still_blocks_after_the_tombstone_gate(self):
        """The other direction: the refusal is not dropped either."""
        ledger = make_ledger()
        tombstones = self._tombstone_set(grant_id="grant-9", action="other")
        registry = RefusalHoldRegistry()
        registry.record("grant-1", "dispatch", "", row=make_row())
        ledger.set_tombstones(tombstones)
        ledger.set_tombstones(registry)
        before = len(ledger)
        with self.assertRaises(ForwardSealError):
            seal(ledger, grant_id="grant-1", action="dispatch", subject="")
        self.assertEqual(len(ledger), before)

    def test_both_gates_are_reachable_at_once(self):
        """Both registries are kept, not just the last one installed."""
        ledger = make_ledger()
        tombstones = self._tombstone_set()
        registry = RefusalHoldRegistry()
        ledger.set_tombstones(tombstones)
        ledger.set_tombstones(registry)
        self.assertIs(ledger.tombstones, registry)
        self.assertIs(ledger.refusals, registry)
        self.assertIs(ledger.cancellations, tombstones)

    def test_installing_the_same_registry_twice_is_not_an_error(self):
        """Re-installing the SAME object is idempotent, not a refusal."""
        ledger = make_ledger()
        registry = RefusalHoldRegistry()
        ledger.set_tombstones(registry)
        ledger.set_tombstones(registry)
        self.assertIs(ledger.refusals, registry)

    def test_a_second_refusal_registry_is_refused_not_swapped(self):
        """A second registry of the same family must not displace the first."""
        ledger = make_ledger()
        registry = RefusalHoldRegistry()
        ledger.set_tombstones(registry)
        with self.assertRaises(ForwardSealError):
            ledger.set_tombstones(RefusalHoldRegistry())
        self.assertIs(ledger.refusals, registry)

    def test_a_second_cancellation_registry_is_refused_not_swapped(self):
        """The same rule for the cancellation family."""
        ledger = make_ledger()
        tombstones = self._tombstone_set()
        ledger.set_tombstones(tombstones)
        with self.assertRaises(ForwardSealError):
            ledger.set_tombstones(self._tombstone_set(grant_id="grant-2"))
        self.assertIs(ledger.cancellations, tombstones)

    def test_a_gate_can_still_be_cleared_explicitly(self):
        """Clearing is a deliberate act, and it clears both families."""
        ledger = make_ledger()
        registry = RefusalHoldRegistry()
        ledger.set_tombstones(registry)
        ledger.set_tombstones(None)
        self.assertIsNone(ledger.refusals)
        self.assertIsNone(ledger.cancellations)

    def test_an_uncovered_action_still_seals_with_both_gates_installed(self):
        """The control: the fix does not block everything."""
        ledger = make_ledger()
        tombstones = self._tombstone_set(grant_id="grant-9", action="other")
        registry = RefusalHoldRegistry()
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        ledger.set_tombstones(tombstones)
        ledger.set_tombstones(registry)
        seal(ledger, grant_id="grant-1", action="dispatch", subject="")
        self.assertEqual(len(ledger), 1)

    def test_an_old_pickle_still_refuses(self):
        """A checkpoint written before the split still blocks.

        The legacy state carried ONE ``_tombstones`` slot.  It is
        restored into the family its shape names, so a checkpoint taken
        before this change keeps refusing what it used to refuse.

        The registry itself holds a lock and is not picklable, so the
        restoration is driven through ``__setstate__`` directly -- which
        is the half of the pickle contract that changed.
        """
        ledger = make_ledger()
        registry = RefusalHoldRegistry()
        registry.record("grant-1", "checkout", "order-7", row=make_row())
        legacy_state = ledger.__getstate__()
        legacy_state.pop("_cancellations", None)
        legacy_state.pop("_refusals", None)
        legacy_state["_tombstones"] = registry
        restored = _legacy_ledger(legacy_state)
        self.assertIs(restored.refusals, registry)
        self.assertIsNone(restored.cancellations)
        before = len(restored)
        with self.assertRaises(ForwardSealError):
            seal(restored)
        self.assertEqual(len(restored), before)


class HostRegistryFamilyTests(unittest.TestCase):
    """A host's OWN registry must be filed by what it DOES.

    THE DEFECT (measured 2026-11-23)
    --------------------------------
    ``_is_refusal_registry`` is documented as classifying the two gate
    families by *"what they return when they block"*:

        the two families are told apart by what they return when they
        block: a **refusal** comes back with the row that refused
        (``row`` and ``row_digest``), a **cancellation** comes back
        with the tombstone that cancelled (neither).

        The test is made on the *declared* surface of the object, not on
        its class name, so a host that writes its own registry is
        classified by what it actually returns rather than by what it
        is called.

    But the implementation reads the **registry's** attributes:

        if getattr(registry, "row", None) is not None:
            return True
        if getattr(registry, "row_digest", None) is not None:
            return True
        return bool(getattr(registry, "is_refusal_registry", False))

    A registry that *returns* a row does not *have* a ``row``
    attribute, so the check reads ``None`` and the registry is filed
    into the **cancellation** family.  Measured on the tree before the
    fix:

        "returns a row"      -> refusal? False     <-- wrong
        "carries .row attr"  -> refusal? True
        "pure cancellation"  -> refusal? False

    The classification is **inverted** with respect to the
    documentation: the two cases are exactly swapped.

    WHY IT MATTERS -- AND IT IS NOT COSMETIC
    ------------------------------------------
    The two families differ in whether the block can be **lifted**.  A
    cancellation can be lifted by a named tombstone-lift; a refusal
    cannot, because "a refusal is not a cancellation".  So a host's own
    refusal registry, filed into the cancellation family, has its
    refusal **lifted**:

        ledger.set_tombstones(host_refusal_registry)
        ledger.append_grant(..., lift=some_lift)
        -> SUCCEEDED      the refusal was lifted

    The house registry, filed correctly, refuses the same seal:

        -> ForwardSealError: a lift was offered but this ledger holds no
           tombstone registry, so nothing can be lifted

    So the defect is not "a host's registry is filed in the wrong
    drawer".  It is "a host's refusal is liftable", which is the one
    thing the refusal gate exists to prevent.

    THE RULE, IN TWO PARTS
    ----------------------
    The fix separates two questions that the old code conflated into
    one:

    1. **Which slot does the registry go in?**  By what it **DECLARES**
       (``is_refusal_registry``, or a row carried on the registry
       itself).  A declaration can be read without asking the registry a
       question, and asking it a question at install time would have
       side effects -- the house registry's ``check`` records an
       **audit event**, so a probe at install time would write a
       phantom event into the trail.

    2. **What does its answer MEAN?**  By the shape of what it
       **RETURNS**.  A result carrying ``row``/``row_digest`` is a
       refusal, and a refusal is refused and is NOT liftable.

    Question 2 is the security question and it holds for an **undeclared**
    host registry too: the seal path reads the ANSWER's shape, so a
    host that installs a registry returning a refusal row without
    declaring itself still cannot have its refusal lifted.  Question 1
    only decides the slot, and declaring into the wrong slot loses
    liftability -- which fails closed, in the safe direction.
    """

    class _HostRefusalRegistry:
        """A host's own registry: TombstoneSet-shaped, returns a row.

        This is exactly the shape ``_is_refusal_registry``'s docstring
        says it classifies by.
        """

        def __init__(self):
            self.lifted = []

        def blocked(self, grant_id, action, subject=None, *, now=None):
            class _Result:
                row = "a-refusal-row"
                row_digest = "sha256:" + "a" * 64

            return _Result()

        def lift(self, lift):
            self.lifted.append(lift)

    class _HostCancellationRegistry:
        """A host's own cancellation registry: returns nothing."""

        def __init__(self):
            self.lifted = []

        def blocked(self, grant_id, action, subject=None, *, now=None):
            return None

        def lift(self, lift):
            self.lifted.append(lift)

    def test_a_declared_refusal_registry_is_filed_into_the_refusal_slot(self):
        """Question 1: the slot comes from the DECLARATION."""
        ledger = make_ledger()
        host = self._HostRefusalRegistry()
        host.is_refusal_registry = True
        ledger.set_tombstones(host)
        self.assertIs(ledger.refusals, host)
        self.assertIsNone(ledger.cancellations)

    def test_a_host_registry_that_returns_nothing_is_the_cancellation_family(self):
        """The control: the fix must not file everything as a refusal."""
        ledger = make_ledger()
        host = self._HostCancellationRegistry()
        ledger.set_tombstones(host)
        self.assertIs(ledger.cancellations, host)
        self.assertIsNone(ledger.refusals)

    def test_an_undeclared_host_registry_is_filed_by_its_declaration(self):
        """An UNDECLARED registry lands in the cancellation slot.

        Filing needs a declaration, because a declaration is the only
        thing readable without asking the registry a question -- and
        asking the house registry a question writes an audit event.

        The undeclared registry is still SAFE: the seal path reads the
        ANSWER's shape, which is the security rule.  That is asserted
        separately, in the tests below.
        """
        ledger = make_ledger()
        host = self._HostRefusalRegistry()
        ledger.set_tombstones(host)
        self.assertIs(ledger.cancellations, host)
        self.assertIsNone(ledger.refusals)

    def test_a_hosts_refusal_cannot_be_lifted(self):
        """The consequence, and the reason the family matters.

        A cancellation can be lifted by a named tombstone-lift.  A
        refusal cannot: "a refusal is not a cancellation and it cannot
        be lifted by a tombstone-lift".  If the family is wrong, the
        refusal becomes liftable -- which is exactly what the refusal
        gate exists to prevent.

        This is the guard that can fail: before the fix, this seal
        SUCCEEDED and ``host.lifted`` held the lift.
        """
        ledger = make_ledger()
        host = self._HostRefusalRegistry()
        ledger.set_tombstones(host)

        class _Lift:
            declarer = "ops"
            declarer_channel = "ops-channel"
            grant_id = "grant-1"
            action = "checkout"

        before = len(ledger)
        with self.assertRaises(ForwardSealError):
            seal(ledger, grant_id="grant-1", action="checkout", subject="order-7",
                 lift=_Lift())
        self.assertEqual(
            len(ledger),
            before,
            "the seal landed even though the refusal covers it",
        )
        self.assertEqual(
            host.lifted,
            [],
            "the host's refusal was LIFTED: a refusal is not a cancellation "
            "and cannot be lifted by a tombstone lift",
        )

    def test_a_declared_refusal_cannot_be_lifted_either(self):
        """The same, for the registry that declared itself.

        The control for the test above: the house path already refused
        this, and the fix must not have changed it.
        """
        ledger = make_ledger()
        host = self._HostRefusalRegistry()
        host.is_refusal_registry = True
        ledger.set_tombstones(host)

        class _Lift:
            declarer = "ops"
            declarer_channel = "ops-channel"
            grant_id = "grant-1"
            action = "checkout"

        with self.assertRaises(ForwardSealError):
            seal(ledger, grant_id="grant-1", action="checkout", subject="order-7",
                 lift=_Lift())
        self.assertEqual(host.lifted, [])

    def test_a_hosts_refusal_is_consulted_before_the_lift_path(self):
        """The refusal family is checked first, on its own terms.

        A host's registry must be asked through the same ``check`` the
        house registry is asked through, so the refusal is refused
        rather than cancelled -- and so the lift path is never reached.
        """
        ledger = make_ledger()
        host = self._HostRefusalRegistry()
        host.is_refusal_registry = True
        ledger.set_tombstones(host)

        with self.assertRaises(ForwardSealError) as caught:
            seal(ledger, grant_id="grant-1", action="checkout", subject="order-7")
        message = str(caught.exception)
        self.assertIn(
            "refused",
            message,
            "the host's refusal was reported as a cancellation",
        )

    def test_the_two_families_stay_distinguishable(self):
        """Both installed at once, each in its own slot."""
        ledger = make_ledger()
        cancellation = self._HostCancellationRegistry()
        refusal = self._HostRefusalRegistry()
        refusal.is_refusal_registry = True
        ledger.set_tombstones(cancellation)
        ledger.set_tombstones(refusal)
        self.assertIs(ledger.cancellations, cancellation)
        self.assertIs(ledger.refusals, refusal)

    def test_a_check_that_answers_nothing_blocks(self):
        """An anomalous ``None`` from ``check`` is a block, not consent.

        ``check`` owes the caller a **reason**: "the caller always gets
        a reason, whether the action is refused, allowed, or the gate
        was unusable".  A ``None`` answer is therefore the gate saying
        *nothing*, and nothing is not permission.

        This guard exists because a mutation that read ``None`` as
        "allowed" SURVIVED the first version of this slice's guards --
        the defect was only found by planting the mutation and re-running.
        """
        ledger = make_ledger()

        class _SilentRegistry:
            """A declared refusal registry that answers with nothing."""

            is_refusal_registry = True

            def check(self, grant_id, action, subject=None, *, now=None):
                return None

            def blocked(self, grant_id, action, subject=None, *, now=None):
                return None

        ledger.set_tombstones(_SilentRegistry())
        before = len(ledger)
        with self.assertRaises(ForwardSealError):
            seal(ledger, grant_id="grant-1", action="checkout", subject="order-7")
        self.assertEqual(
            len(ledger),
            before,
            "a gate that answered nothing was read as a gate that allowed it",
        )

    def test_a_blocked_that_answers_none_does_not_block(self):
        """The control for the test above: ``blocked``'s ``None`` means no block.

        ``blocked`` answers ``None`` for *not blocked* -- that is the
        ``TombstoneSet`` contract, and it must keep working.
        """
        ledger = make_ledger()

        class _QuietRegistry:
            """A declared refusal registry whose ``blocked`` says 'no block'."""

            is_refusal_registry = True

            def blocked(self, grant_id, action, subject=None, *, now=None):
                return None

        ledger.set_tombstones(_QuietRegistry())
        seal(ledger, grant_id="grant-1", action="checkout", subject="order-7")
        self.assertEqual(len(ledger), 1)

    def test_a_gate_that_raises_blocks(self):
        """A gate that cannot answer blocks -- it does not allow.

        "The gate could not answer" is not "the gate allowed it".  A
        registry whose ``check`` raises has not said anything about
        this action, so the seal is refused.

        This guard exists because a mutation that swallowed the raising
        gate's exception SURVIVED the first version of this slice's
        guards: the swallowed exception was read as "not blocked", and
        the seal was ALLOWED.  A mutation run that produces
        ``78 passed`` where the defect is planted is a hole in the
        guard, not a pass.
        """
        ledger = make_ledger()

        class _BrokenRegistry:
            """A declared refusal registry that cannot answer."""

            is_refusal_registry = True

            def check(self, grant_id, action, subject=None, *, now=None):
                raise RuntimeError("the store is unreadable")

            def blocked(self, grant_id, action, subject=None, *, now=None):
                raise RuntimeError("the store is unreadable")

        ledger.set_tombstones(_BrokenRegistry())
        before = len(ledger)
        with self.assertRaises(ForwardSealError):
            seal(ledger, grant_id="grant-1", action="checkout", subject="order-7")
        self.assertEqual(
            len(ledger),
            before,
            "a gate that could not answer was read as a gate that allowed it",
        )

    def test_a_gate_that_answers_neither_method_blocks(self):
        """A registry with no way to answer blocks.

        The refusal family answers through ``check`` or ``blocked``.  A
        registry that offers neither cannot be consulted, and a gate
        that cannot be consulted must not be read as a gate that allowed
        the action.
        """
        ledger = make_ledger()

        class _MuteRegistry:
            """A declared refusal registry with no query method."""

            is_refusal_registry = True

        ledger.set_tombstones(_MuteRegistry())
        before = len(ledger)
        with self.assertRaises(ForwardSealError) as caught:
            seal(ledger, grant_id="grant-1", action="checkout", subject="order-7")
        self.assertEqual(
            len(ledger),
            before,
            "a gate that could not be consulted was read as a gate that "
            "allowed it",
        )
        # The MESSAGE is the assertion that makes this guard
        # load-bearing.  Without the explicit "can answer neither"
        # branch, the registry falls through to calling a missing
        # method, and the resulting ``TypeError`` is caught by the
        # generic handler -- which fails closed BY ACCIDENT, with a
        # different message ("could not answer").  That accidental
        # safety is exactly what a mutation run exposes: the guard
        # would be deleted and every test would still pass.
        self.assertIn(
            "can answer neither",
            str(caught.exception),
            "the seal was refused for the wrong reason: the gate could not "
            "be consulted, and that must be said rather than inferred "
            "from a TypeError",
        )

    def test_a_cancellation_is_still_liftable(self):
        """The control for the backstop: a real tombstone still lifts.

        The backstop refuses a block whose answer carries a refusal
        row.  A ``Tombstone`` carries neither ``row`` nor
        ``row_digest``, so a genuine cancellation is unaffected -- and
        this test is what proves the backstop did not simply refuse
        every lift.
        """
        from cancellation_tombstone import Lift, Tombstone, TombstoneSet

        ledger = make_ledger()
        tombstones = TombstoneSet(
            [
                Tombstone(
                    grant_id="grant-1",
                    action="checkout",
                    subject="order-7",
                    declarer="ops",
                    declarer_channel="ops-channel",
                )
            ]
        )
        ledger.set_tombstones(tombstones)

        lift = Lift(
            declarer="ops",
            declarer_channel="ops-channel",
            grant_id="grant-1",
            action="checkout",
            subject="order-7",
        )
        seal(ledger, grant_id="grant-1", action="checkout", subject="order-7",
             lift=lift)
        self.assertEqual(len(ledger), 1, "a genuine cancellation must still lift")


def _legacy_ledger(state):
    """A ledger rebuilt from a legacy (pre-split) pickle state.

    The ledger is built from ``_FSL`` -- **this file's own** binding of
    the module -- and not from a fresh ``import forward_seal_ledger``
    inside the function.

    That is not a style choice.  ``tests/test_forward_seal_ledger.py``
    replaces ``sys.modules["forward_seal_ledger"]`` with a freshly
    executed copy of the same source at ITS import time.  A function-level
    ``import`` inside this file therefore resolves to whatever module is
    CURRENTLY registered, while this file's module-level
    ``from forward_seal_ledger import ForwardSealError`` bound to the
    module that was registered when THIS file was imported.

    Two module objects, two distinct ``ForwardSealError`` classes, one
    name.  A ledger built from the current module raises the current
    class; ``assertRaises(ForwardSealError)`` -- the class bound above --
    watches the other one, and the assertion fails even though the
    refusal happened exactly as it should.

    Measured 2026-11-21: this failed in the full-suite discovery and
    passed in isolation, because only the full-suite import order puts a
    different module in ``sys.modules`` first.  Building from ``_FSL``
    keeps the ledger and the asserted class in one module, so the test
    means the same thing in both orders.
    """
    ledger = _FSL.ForwardSealLedger.__new__(_FSL.ForwardSealLedger)
    ledger.__setstate__(state)
    return ledger


class RegistryCapacityTests(unittest.TestCase):
    """The registry must not half-record a refusal it cannot store.

    THE DEFECT (measured 2026-11-23)
    --------------------------------
    ``RefusalHoldRegistry.record_entry()`` appends to ``self._entries``
    and THEN rebuilds the store.  The rebuild is what enforces the
    hold's bound (``MAX_HOLD_ENTRIES``), and it raises when the bound
    is passed -- so the append has already happened when the raise
    arrives.

    Measured on the tree before the fix:

        reg._entries len  : 256        # the store's bound
        reg.hold entries  : 256
        reg.store entries : 256
        to_dict entries   : 256
        events            : 256

        FAILED RECORD: RefusalHoldWiringError wiring: a hold carries at
                        most 256 refusals, got 257

        AFTER the failed record:
        reg._entries len  : 257        # <-- grew, despite the failure
        reg.hold entries  : 256
        reg.store entries : 256
        to_dict entries   : 257        # <-- and is now UNRECONSTRUCTIBLE
        events            : 256

    Three consequences, in increasing order of severity:

    1. **The registry's own view of itself is a lie.**  ``to_dict()``
       reports 257 entries while the store holds 256, so the two
       disagree about what was recorded.

    2. **The registry can no longer be rebuilt.**  ``to_dict()`` is the
       shape a host persists and restores, and restoring it raises:
       ``a hold carries at most 256 refusals, got 257``.  A host that
       persisted a registry and tried to restore it gets a hard
       failure -- and it gets it *because* of a record that was
       REFUSED.

    3. **The refusal mechanism is FROZEN.**  Every subsequent record
       fails the same way, because the store is already at its bound
       and the refused append keeps pushing ``_entries`` further past
       it.  Measured: after the first failure, three further records
       all failed and ``_entries`` grew to 259; after 200 more failed
       records ``_entries`` was 459 while the store stayed at 256.  So
       the registry grows without bound and stores nothing new: a host
       that records refusals for more than 256 actions has a gate that
       can no longer refuse anything it is asked about afterwards.

    The direction of the failure is what makes it a defect: the
    registry **silently accepted** a write it then refused, and it
    never recovered.

    THE RULE
    --------
    A refused record must leave the registry **exactly** as it was:
    the same entries, the same store, the same ``to_dict()``, the same
    event trail.  The bound must be checked BEFORE the mutation, the
    way ``cancellation_tombstone.TombstoneSet`` checks
    ``MAX_TOMBSTONES`` before it adds -- see
    ``TombstoneSet.add``::

        if len(self._tombstones) >= MAX_TOMBSTONES:
            raise TombstoneError(...)

    A **duplicate** key is not a new refusal and must not consume a
    slot of the bound either: re-recording the same key is a no-op for
    the store (the store returns the FIRST matching entry), so it
    must be a no-op for the registry too.
    """

    def _fill(self, registry, count, prefix="job"):
        """Record ``count`` refusals, one per distinct key."""
        for index in range(count):
            registry.record(
                f"{prefix}-{index}", "dispatch", row=make_row(f"r{index}")
            )

    def test_a_refused_record_leaves_the_entries_unchanged(self):
        from refusal_hold import MAX_HOLD_ENTRIES

        registry = RefusalHoldRegistry()
        self._fill(registry, MAX_HOLD_ENTRIES)
        before = len(registry.to_dict()["entries"])

        with self.assertRaises(RefusalHoldWiringError):
            registry.record("one-too-many", "dispatch", row=make_row("over"))

        self.assertEqual(
            len(registry.to_dict()["entries"]),
            before,
            "a refused record must not add an entry",
        )

    def test_the_registry_and_its_store_agree_after_a_refused_record(self):
        """``to_dict()`` and the store must not disagree about the record.

        This is the observable that caught the defect: the registry
        counted 257 and the store counted 256.
        """
        from refusal_hold import MAX_HOLD_ENTRIES

        registry = RefusalHoldRegistry()
        self._fill(registry, MAX_HOLD_ENTRIES)

        with self.assertRaises(RefusalHoldWiringError):
            registry.record("one-too-many", "dispatch", row=make_row("over"))

        self.assertEqual(
            len(registry.to_dict()["entries"]),
            len(registry.store.entries()),
            "the registry's serialization and its store must agree",
        )

    def test_a_refused_record_leaves_to_dict_reconstructible(self):
        """The registry's own serialization must still restore."""
        from refusal_hold import MAX_HOLD_ENTRIES

        registry = RefusalHoldRegistry()
        self._fill(registry, MAX_HOLD_ENTRIES)

        with self.assertRaises(RefusalHoldWiringError):
            registry.record("one-too-many", "dispatch", row=make_row("over"))

        payload = registry.to_dict()
        self.assertEqual(
            len(payload["entries"]),
            MAX_HOLD_ENTRIES,
            "to_dict() must agree with the store about what was recorded",
        )
        # And the payload must actually restore.
        restored = RefusalHoldRegistry()
        self.assertEqual(len(restored.hold.entries()), 0)
        for entry in payload["entries"]:
            restored.record(
                entry["scope_id"],
                entry["action"],
                row=make_row(entry["row"]["reason"]),
            )
        self.assertEqual(len(restored.hold.entries()), MAX_HOLD_ENTRIES)

    def test_a_refused_record_leaves_the_events_unchanged(self):
        from refusal_hold import MAX_HOLD_ENTRIES

        registry = RefusalHoldRegistry()
        self._fill(registry, MAX_HOLD_ENTRIES)
        before = len(registry.events())

        with self.assertRaises(RefusalHoldWiringError):
            registry.record("one-too-many", "dispatch", row=make_row("over"))

        self.assertEqual(
            len(registry.events()),
            before,
            "a refused record must not leave an event behind",
        )

    def test_a_refused_record_does_not_freeze_the_registry(self):
        """After the bound is hit, the registry still answers for what it has."""
        from refusal_hold import MAX_HOLD_ENTRIES

        registry = RefusalHoldRegistry()
        self._fill(registry, MAX_HOLD_ENTRIES)

        with self.assertRaises(RefusalHoldWiringError):
            registry.record("one-too-many", "dispatch", row=make_row("over"))

        # The refusals that DID land still refuse.
        result = registry.check(f"job-0", "dispatch")
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_BY_REFUSAL)

        # And the refusal that did NOT land is simply not there -- it is
        # not a hole in the gate, it is an absence, and the gate says so.
        absent = registry.check("one-too-many", "dispatch")
        self.assertFalse(absent.blocked)
        self.assertEqual(absent.reason, REASON_ALLOWED_NO_REFUSAL)

    def test_the_registry_does_not_grow_without_bound(self):
        """A refused record must not leak an entry per attempt."""
        from refusal_hold import MAX_HOLD_ENTRIES

        registry = RefusalHoldRegistry()
        self._fill(registry, MAX_HOLD_ENTRIES)
        before = len(registry.to_dict()["entries"])

        for index in range(50):
            with self.assertRaises(RefusalHoldWiringError):
                registry.record(f"spam-{index}", "dispatch", row=make_row("x"))

        self.assertEqual(
            len(registry.to_dict()["entries"]),
            before,
            "the registry must not grow past the bound on refused records",
        )

    def test_a_duplicate_key_does_not_consume_a_second_slot(self):
        """Re-recording the same key is a no-op, not a new entry."""
        from refusal_hold import MAX_HOLD_ENTRIES

        registry = RefusalHoldRegistry()
        registry.record("job-1", "dispatch", row=make_row("first"))
        registry.record("job-1", "dispatch", row=make_row("second"))

        self.assertEqual(
            len(registry.to_dict()["entries"]),
            1,
            "the same key recorded twice is one refusal",
        )

    def test_a_duplicate_key_is_refused_at_the_bound(self):
        """At the bound, re-recording an existing key still works.

        The duplicate does not need a new slot, so the bound does not
        apply to it -- and the refusal it carries stays the one that is
        already on the books.
        """
        from refusal_hold import MAX_HOLD_ENTRIES

        registry = RefusalHoldRegistry()
        self._fill(registry, MAX_HOLD_ENTRIES)

        # job-0 is already recorded, so this needs no new slot.
        registry.record("job-0", "dispatch", row=make_row("again"))
        self.assertEqual(
            len(registry.to_dict()["entries"]), MAX_HOLD_ENTRIES
        )

        result = registry.check("job-0", "dispatch")
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_BY_REFUSAL)


class RegistryHostStoreTests(unittest.TestCase):
    """A host's OWN store must survive the registry's construction.

    THE DEFECT (measured 2026-11-23)
    --------------------------------
    ``RefusalHoldRegistry.__init__`` accepts a ``hold`` -- and the hold
    may carry a **host's own store** (the docstring of
    ``RefusalHoldStore`` says so: "A caller with rows on disk supplies
    its own store; the hold only requires the store to answer
    ``fetch``").  But the registry does not keep the hold's store: it
    builds a **fresh** ``RefusalHoldStore(self._entries)`` and a fresh
    hold over it.

    So two things the host configured are silently dropped:

    * the host's store **readable flag** -- a store the host broke (or
      one that is unreadable because the disk is gone) comes back
      READABLE.  Measured before the fix:

          the hold's own answer (broken store): blocked_store_unreadable
          REGISTRY store readable after construction: True
          registry check: blocked_by_refusal

      The direction is **fail OPEN**: the registry's own contract says
      "a broken gate blocks" and "an unreadable store is not a clean
      read: it blocks", and the construction path turns a blocked
      answer into an allowed one.

    * the host's store **contents** -- a store that carries the host's
      rows (the shape ``RefusalHold(entries=[], store=disk_store)``
      produces) is emptied by the registry.  Measured before the fix:

          the HOLD's own answer for job-1: blocked_by_refusal
          the REGISTRY's answer for job-1: allowed_no_refusal
          registry entries: 0   store entries: 0

      A host that loaded its refusals from disk and handed them to the
      registry gets a gate that **knows about no refusals at all** --
      and the answer is "allowed".  That is the one answer that must
      never be given by accident.

    The registry's own ``_rebuild_store`` already knows the rule -- "A
    store that was broken stays broken: a recording must not heal the
    gate" -- but it only honours it for the store the registry itself
    owns.  The construction path never went through it.

    THE RULE
    --------
    The registry is a **view** over a hold.  When it is handed a hold,
    it must read the same store the hold reads, and it must carry the
    store's unreadable state with it.
    """

    def _host_store(self, rows=1, broken=False):
        from refusal_hold import RefusalHoldEntry, RefusalHoldStore
        from refusal_hold_wiring import queue_hold_key

        entries = [
            RefusalHoldEntry(
                key=queue_hold_key(f"job-{index}", "dispatch"), row=make_row()
            )
            for index in range(rows)
        ]
        store = RefusalHoldStore(entries)
        if broken:
            store.break_reads()
        return store

    def test_a_broken_host_store_stays_broken(self):
        from refusal_hold import RefusalHold

        store = self._host_store(rows=1, broken=True)
        hold = RefusalHold(entries=[], store=store)
        self.assertTrue(hold.check(queue_hold_key("job-0", "dispatch")).blocked)

        registry = RefusalHoldRegistry(hold=hold)

        self.assertFalse(
            registry.store.is_readable(),
            "the registry must not heal a broken host store",
        )
        result = registry.check_key(queue_hold_key("job-0", "dispatch"))
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_STORE_UNREADABLE)

    def test_a_host_store_with_rows_is_not_emptied(self):
        from refusal_hold import RefusalHold

        store = self._host_store(rows=2)
        hold = RefusalHold(entries=[], store=store)

        registry = RefusalHoldRegistry(hold=hold)

        result = registry.check_key(queue_hold_key("job-0", "dispatch"))
        self.assertTrue(
            result.blocked,
            "the host's refusals must still be refusals after construction",
        )
        self.assertEqual(result.reason, REASON_BLOCKED_BY_REFUSAL)

    def test_a_host_store_with_rows_is_the_registry_store(self):
        from refusal_hold import RefusalHold

        store = self._host_store(rows=1)
        hold = RefusalHold(entries=[], store=store)

        registry = RefusalHoldRegistry(hold=hold)

        self.assertIs(
            registry.store,
            store,
            "the registry must read the store it was handed",
        )

    def test_a_recording_does_not_drop_the_host_s_rows(self):
        """The rebuild must not discard what the host had loaded.

        This is the SECOND half of the defect: construction was fixed,
        but the first recording rebuilt the store from the registry's
        own entries -- which, for a registry built over a host store,
        were empty -- so the recording dropped every refusal the host
        had loaded.  Measured before the fix:

            before record: check job-1 = blocked_by_refusal
            AFTER  record: check job-1 = allowed_no_refusal
        """
        from refusal_hold import RefusalHold

        store = self._host_store(rows=1)
        hold = RefusalHold(entries=[], store=store)
        registry = RefusalHoldRegistry(hold=hold)

        self.assertTrue(registry.check_key(queue_hold_key("job-0", "dispatch")).blocked)

        registry.record("grant-1", "dispatch", row=make_row("new"))

        result = registry.check_key(queue_hold_key("job-0", "dispatch"))
        self.assertTrue(
            result.blocked,
            "the host's refusal must survive a recording",
        )
        self.assertEqual(result.reason, REASON_BLOCKED_BY_REFUSAL)

    def test_a_broken_host_store_stays_broken_after_a_recording(self):
        """A recording must not heal a broken host store either."""
        from refusal_hold import RefusalHold

        store = self._host_store(rows=1, broken=True)
        hold = RefusalHold(entries=[], store=store)
        registry = RefusalHoldRegistry(hold=hold)

        registry.record("grant-1", "dispatch", row=make_row("new"))

        self.assertFalse(registry.store.is_readable())
        result = registry.check_key(queue_hold_key("job-0", "dispatch"))
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_STORE_UNREADABLE)


if __name__ == "__main__":
    unittest.main()
