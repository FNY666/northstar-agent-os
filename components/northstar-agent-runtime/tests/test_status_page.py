"""Tests for status_page (Statuspage.io-shaped incident bookkeeping)."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import status_page as sp

THIS_DIR = Path(__file__).resolve().parent.parent


def fresh(seed: str = "test") -> sp.StatusPage:
    return sp.StatusPage(seed=seed)


# -- pins --------------------------------------------------------------


def test_pins():
    assert sp.STATUS_PAGE_VERSION == "status-page.v1"
    assert sp.STATUS_PAGE_SCHEMA == "northstar.status-page.v1"
    assert sp.COMPONENT_STATUSES == (
        "operational",
        "degraded",
        "partial-outage",
        "major-outage",
        "maintenance",
    )
    assert sp.INCIDENT_STATUSES == (
        "investigating",
        "identified",
        "monitoring",
        "resolved",
    )
    assert sp.IMPACTS == ("none", "minor", "major", "critical")
    assert set(sp._KINDS) == {
        "status.component-registered",
        "status.component-status-set",
        "status.incident-created",
        "status.incident-updated",
        "status.incident-resolved",
        "status.rejected",
    }


def test_stdlib_only():
    tree = ast.parse((THIS_DIR / "status_page.py").read_text())
    allowed = {
        "hashlib",
        "hmac",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "__future__",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# -- components --------------------------------------------------------


def test_component_roundtrip():
    page = fresh()
    rec = page.component("api", "Public API", 0, group="core")
    assert rec.component_id == "api"
    assert rec.name == "Public API"
    assert rec.status == "operational"
    assert rec.group == "core"
    assert rec.verify(seed="test")
    assert page.component_ids() == ("api",)
    assert page.component_record("api") == rec


def test_component_bad_inputs_and_duplicate():
    page = fresh()
    with pytest.raises(sp.DuplicateComponentError):
        page.component("api", "Public API", 0)
        page.component("api", "Public API", 1)
    seq = 1
    for bad_id in ("", "  ", "has space"):
        seq += 1
        with pytest.raises(sp.StatusPageError):
            page.component(bad_id, "Name", seq)
    with pytest.raises(sp.UnknownComponentError):
        page.component_record("nope")


def test_set_status_roundtrip_and_history_chain():
    page = fresh()
    page.component("api", "Public API", 0)
    c1 = page.set_status("api", sp.STATUS_DEGRADED, 1)
    c2 = page.set_status("api", sp.STATUS_MAJOR_OUTAGE, 2)
    assert c1.change_id == "chg-1" and c1.prev_digest == "genesis"
    assert c2.prev_digest == c1.digest
    assert c1.verify(seed="test") and c2.verify(seed="test")
    assert page.component_record("api").status == sp.STATUS_MAJOR_OUTAGE
    hist = page.status_history("api")
    assert [c.change_id for c in hist] == ["chg-1", "chg-2"]
    with pytest.raises(sp.BadStatusError):
        page.set_status("api", "on-fire", 3)
    with pytest.raises(sp.UnknownComponentError):
        page.set_status("db", sp.STATUS_DEGRADED, 4)


# -- incidents ---------------------------------------------------------


def test_incident_roundtrip():
    page = fresh()
    page.component("api", "Public API", 0)
    inc = page.incident("inc-1", "API elevated errors", 1, ("api",), sp.IMPACT_MAJOR)
    assert inc.status == sp.INCIDENT_INVESTIGATING
    assert inc.impact == sp.IMPACT_MAJOR
    assert inc.component_ids == ("api",)
    assert inc.verify(seed="test")
    assert page.incident_ids() == ("inc-1",)
    with pytest.raises(sp.DuplicateIncidentError):
        page.incident("inc-1", "Again", 2)
    with pytest.raises(sp.BadIncidentError):
        page.incident("inc-2", "Ghost", 3, ("nope",))
    with pytest.raises(sp.UnknownIncidentError):
        page.incident_record("nope")


def test_update_feed_and_chaining():
    page = fresh()
    page.component("api", "Public API", 0)
    page.incident("inc-1", "API elevated errors", 1, ("api",))
    u1 = page.update("inc-1", sp.INCIDENT_IDENTIFIED, "Bad deploy, rolling back", 2)
    u2 = page.update("inc-1", sp.INCIDENT_MONITORING, "Error rate falling", 3)
    assert u1.update_id == "upd-1" and u1.prev_digest == "genesis"
    assert u2.prev_digest == u1.digest
    assert u1.verify(seed="test") and u2.verify(seed="test")
    assert page.incident_record("inc-1").status == sp.INCIDENT_MONITORING
    feed = page.updates_for("inc-1")
    assert [u.update_id for u in feed] == ["upd-1", "upd-2"]
    with pytest.raises(sp.BadUpdateError):
        page.update("inc-1", sp.INCIDENT_RESOLVED, "Wrong path", 4)
    with pytest.raises(sp.UnknownIncidentError):
        page.update("inc-9", sp.INCIDENT_IDENTIFIED, "Nope", 5)


def test_resolve_terminal():
    page = fresh()
    page.component("api", "Public API", 0)
    page.incident("inc-1", "API elevated errors", 1, ("api",))
    res = page.resolve("inc-1", "Errors back to baseline", 2)
    assert res.resolution_id == "res-1" and res.verify(seed="test")
    assert page.incident_record("inc-1").status == sp.INCIDENT_RESOLVED
    assert page.resolution_for("inc-1") == res
    with pytest.raises(sp.AlreadyResolvedError):
        page.update("inc-1", sp.INCIDENT_MONITORING, "Too late", 3)
    with pytest.raises(sp.AlreadyResolvedError):
        page.resolve("inc-1", "Twice", 4)


# -- seq discipline ----------------------------------------------------


def test_seq_rewind_bool_and_burn():
    page = fresh()
    page.component("api", "Public API", 0)
    n0 = len(page.audit_log())
    with pytest.raises(sp.SeqOrderError):
        page.set_status("api", sp.STATUS_DEGRADED, 0)  # rewind
    assert len(page.audit_log()) == n0  # seq not consumed on shape refusal
    with pytest.raises(sp.StatusPageError):
        page.set_status("api", sp.STATUS_DEGRADED, True)  # bool refused
    with pytest.raises(sp.BadStatusError):
        page.set_status("api", "nope", 1)  # bad value: seq consumed + rejected
    assert page.audit_log()[-1]["kind"] == "status.rejected"
    with pytest.raises(sp.SeqOrderError):
        page.set_status("api", sp.STATUS_DEGRADED, 1)  # burned


# -- aggregate view ----------------------------------------------------


def test_page_status_aggregate():
    page = fresh()
    page.component("api", "Public API", 0)
    page.component("db", "Database", 1)
    v1 = page.page_status(2)
    assert v1.overall == "operational" and v1.component_count == 2
    assert v1.open_incidents == 0 and v1.verify(seed="test")
    page.set_status("db", sp.STATUS_PARTIAL_OUTAGE, 3)
    page.set_status("api", sp.STATUS_DEGRADED, 4)
    page.incident("inc-1", "DB failover", 5, ("db",))
    v2 = page.page_status(6)
    assert v2.overall == "partial-outage"  # worst wins
    assert v2.open_incidents == 1
    assert v2.verify(seed="test")
    assert v2.seq == 6
    # view is read-only: incident still open, no seq consumed
    assert page.incident_record("inc-1").status == sp.INCIDENT_INVESTIGATING


# -- audit -------------------------------------------------------------


def test_audit_shapes_and_message_ban():
    page = fresh()
    page.component("api", "Public API", 0)
    page.set_status("api", sp.STATUS_DEGRADED, 1)
    kinds = [e["kind"] for e in page.audit_log()]
    assert kinds == ["status.component-registered", "status.component-status-set"]
    for e in page.audit_log():
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "status_page"
        assert e["module_version"] == "status-page.v1"
        assert "message" not in e["detail"]
    with pytest.raises(sp.StatusPageError):
        sp.status_page_audit_event("status.incident-updated", 2, message="leak")
    with pytest.raises(sp.StatusPageError):
        sp.status_page_audit_event("bogus.kind", 2)


def test_cross_instance_digest_determinism():
    a, b = fresh(seed="same"), fresh(seed="same")
    a.component("api", "Public API", 0)
    b.component("api", "Public API", 0)
    assert a.component_record("api").digest == b.component_record("api").digest


def test_lookup_errors_and_history_filtering():
    page = fresh()
    page.component("api", "Public API", 0)
    page.component("db", "Database", 1)
    page.set_status("api", sp.STATUS_DEGRADED, 2)
    page.incident("inc-1", "API elevated errors", 3, ("api",))
    with pytest.raises(sp.UnknownComponentError):
        page.status_history("nope")
    hist = page.status_history("db")
    assert hist == ()  # db had no changes; history is per-component
    assert len(page.status_history("api")) == 1
    with pytest.raises(sp.StatusPageError):
        page.resolution_for("inc-1")  # unresolved
    with pytest.raises(sp.UnknownIncidentError):
        page.updates_for("nope")


def test_thread_safety_smoke():
    import threading

    page = fresh()
    errors = []

    def worker(i: int):
        try:
            page.component(f"c-{i}", f"Comp {i}", i)
        except sp.StatusPageError as exc:  # seq races are fail-closed, not crashes
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert page.component_ids()  # at least one won the seq race


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(THIS_DIR / "status_page.py")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "status-page OK" in proc.stdout


# -- the digest pin must pin --------------------------------------------
#
# Four defects, the same four `graph_database.py` carried (see
# `docs/design/graph-database-digest-pin.md` and
# `docs/design/refusal-hold-wiring.md` section 20.6, which left
# "the identical clause ... for a slice that owns" that module).
# Measured 2026-11-25 on the tree as it stood:
#
# 1. `StatusPage.component(component_id="\ud800", ...)` raised
#    `canonical_json.JcsError` -- a `ValueError`, but NOT a
#    `StatusPageError` -- so the module's guards did not catch it, and
#    the caller's own error taxonomy was bypassed.
# 2. The stdlib fallback ACCEPTED a lone surrogate and produced
#    non-JCS bytes: `b'{"t":"list","v":[{"t":"str","v":"\\ud800"}]}'`.
# 3. `canonical_json` serializes an integer outside the safe range as
#    an IEEE-754 double (RFC 8785 Appendix B note (2)), so 2**53 and
#    2**53+1 canonicalize to the SAME bytes -- and `_check_seq` has no
#    bound at all, so a TAMPERED seq above the safe range still
#    verified.
# 4. A failed pin booked NO `rejected` row: the `_pin(...)` calls sit
#    outside the `try` that books the row.


SURROGATE = "\ud800"


def test_verify_answers_false_for_a_record_it_cannot_canonicalize():
    """`verify()` answers a question; a question is not an exception.

    The record's digest cannot be recomputed over a lone surrogate, so
    the answer is "not intact" -- `False`.  It must not raise.
    """
    rec = sp.ComponentRecord(
        component_id=SURROGATE,
        name="n",
        status=sp.STATUS_OPERATIONAL,
        group="g",
        seq=1,
        digest="sha256:" + "0" * 64,
    )
    assert rec.verify() is False


def test_a_refusal_raises_the_modules_own_error_type():
    """The module's own taxonomy, not the sibling helper's.

    `JcsError` is a `ValueError`, so a caller guarding on
    `except ValueError` would treat a refused mutation as a parse
    error.  The module's error must be what escapes.
    """
    page = fresh()
    with pytest.raises(sp.StatusPageError):
        page.component(component_id=SURROGATE, name="n", seq=1)


def test_both_configurations_refuse_a_lone_surrogate():
    """The shipped path and the fallback must agree about LEGALITY.

    They need not agree about the resulting digest bytes -- the
    fallback's tagged form is deliberately its own string -- but a value
    one refuses must be refused by both.
    """
    saved = sp._cj
    try:
        assert sp._cj is not None, "the shipped path is not installed"

        sp._cj = saved
        with pytest.raises(sp.StatusPageError):
            sp._canonical([SURROGATE])

        sp._cj = None
        with pytest.raises(sp.StatusPageError):
            sp._canonical([SURROGATE])
    finally:
        sp._cj = saved


def test_both_configurations_accept_a_value_both_can_canonicalize():
    """The control: the fallback must not refuse everything.

    Without this, a fallback that refused every input would satisfy
    the test above vacuously.
    """
    saved = sp._cj
    try:
        for cfg in (saved, None):
            sp._cj = cfg
            assert sp._canonical(["ordinary", 7, ["a"]])
    finally:
        sp._cj = saved


def test_a_seq_above_the_safe_range_is_refused():
    """A seq that cannot be pinned must not be accepted.

    Without this bound, 2**53 and 2**53+1 canonicalize to the same
    bytes, so the digest stops pinning the seq.
    """
    page = fresh()
    with pytest.raises(sp.StatusPageError):
        page.component(component_id="c", name="n", seq=2**53)


def test_a_tampered_seq_above_the_safe_range_cannot_verify():
    """The control: the digest must pin the seq.

    This is the property the bound protects -- a record whose seq was
    bumped by one must not still verify.
    """
    digest = sp._pin(["component", "c", "n", sp.STATUS_OPERATIONAL, "g", 1])
    tampered = sp.ComponentRecord(
        component_id="c",
        name="n",
        status=sp.STATUS_OPERATIONAL,
        group="g",
        seq=2**53 + 1,
        digest=digest,
    )
    assert tampered.verify() is False


def test_the_safe_range_boundary_is_accepted():
    """The control: the bound must not over-refuse.

    `2**53 - 1` is the last pin-able integer.
    """
    page = fresh()
    page.component(component_id="c", name="n", seq=2**53 - 1)
    with pytest.raises(sp.StatusPageError):
        page.component(component_id="c2", name="n", seq=2**53)


def test_a_failed_mutation_books_a_rejected_row():
    """A refused mutation must leave a trace.

    The class docstring promises that failed mutations consume their
    seq and book a `rejected` audit row.  A failed PIN is a refusal
    too, and it must book one.
    """
    page = fresh()
    before = len(page.audit_log())

    with pytest.raises(sp.StatusPageError):
        page.component(component_id=SURROGATE, name="n", seq=1)

    rows = page.audit_log()
    assert len(rows) == before + 1, (
        "a failed mutation booked no row: the trail cannot tell a "
        "refusal from a never-seen request"
    )
    assert rows[-1]["kind"] == sp.KIND_REJECTED
    assert rows[-1]["detail"].get("reason"), "the rejection row names no reason"


def test_a_failed_mutation_still_consumes_its_seq():
    """The other half of the promise: the seq is consumed."""
    page = fresh()
    with pytest.raises(sp.StatusPageError):
        page.component(component_id=SURROGATE, name="n", seq=1)

    with pytest.raises(sp.StatusPageError):
        page.component(component_id="c", name="n", seq=1)
    page.component(component_id="c", name="n", seq=2)
    assert "c" in page.component_ids()


def test_a_pin_refuses_an_integer_outside_the_safe_range():
    """No digest may ever be minted over a lossy integer.

    THIS is the property that closes the collision.  Without it,
    `_pin([..., 2**53])` and `_pin([..., 2**53+1])` produce the SAME
    digest -- both canonicalize to the bytes `9007199254740992` -- and
    a record carrying either digest verifies against either seq.

    The tampered-seq test above cannot see this: it was false because
    the digest did not match, not because the pin refused.  So it
    asserts the MECHANISM here.

    The recursion matters: the payload is a nested list of pin parts,
    so a top-level-only check would miss the integer entirely.
    """
    for part in (2**53, 2**53 + 1, 2**60, -(2**53)):
        with pytest.raises(sp.StatusPageError):
            sp._pin(["component", "c", "n", sp.STATUS_OPERATIONAL, "g", part])


def test_a_pin_still_accepts_the_last_safe_integer():
    """The control: the refusal must not over-reach.

    `2**53 - 1` is the last integer whose canonical form is exact.
    """
    pinned = sp._pin(["component", "c", "n", sp.STATUS_OPERATIONAL, "g", 2**53 - 1])
    assert pinned.startswith("sha256:")


def test_an_oversized_seq_is_refused_as_a_malformed_seq():
    """The refusal's SHAPE must match the repo's convention.

    An oversized seq is a malformed **seq**, not a malformed
    argument: the call never reached the ledger, so it consumes
    nothing and books nothing.  A malformed **argument** at a valid
    seq consumes the seq and books a row.

    This is the repo's house rule -- see
    ``docs/design/refusal-hold-wiring.md`` section 21.3, and
    ``job_queue.py``'s ``_check_seq``.

    Why this test distinguishes the bound from the pin refusal: BOTH
    raise ``StatusPageError``, so "it raised" cannot tell them apart.
    What tells them apart is whether the seq was CONSUMED and whether
    a ROW was booked.  A refusal at the door consumes nothing and
    books nothing.
    """
    page = fresh()
    with pytest.raises(sp.StatusPageError):
        page.component(component_id="c", name="n", seq=2**53)

    # nothing was booked -- the call never reached the ledger
    assert page.audit_log() == (), (
        "an oversized seq booked a row: it was refused at the door, "
        "so the ledger never saw it"
    )
    # and the seq was not consumed, so a normal seq still works
    page.component(component_id="c", name="n", seq=1)
    assert "c" in page.component_ids()


def test_the_seq_bound_refuses_before_the_pin_would():
    """The control: the bound is what refuses, not the pin.

    Without the bound, the oversized seq would reach ``_pin``, and
    the pin's own refusal (``_refuse_unsafe_int``) would raise the
    SAME error type -- so the caller could not tell whether the seq
    was checked at the door or caught later.

    The distinguishing fact: with the bound, the seq is NOT consumed
    and NO row is booked (the call never reached the ledger).  Without
    it, the pin failure would happen inside the mutation and would
    consume the seq and book a row.

    So: an oversized seq that books a row, or that consumes the seq,
    means the bound is missing.
    """
    page = fresh()
    with pytest.raises(sp.StatusPageError):
        page.component(component_id="c", name="n", seq=2**53)
    # If the bound were missing, the pin would have failed INSIDE the
    # mutation, consuming the seq and booking a row.  Assert both are
    # absent.
    assert page.audit_log() == ()
    # seq 1 must still be usable -- the oversized seq never took it.
    page.component(component_id="c", name="n", seq=1)
    assert "c" in page.component_ids()
