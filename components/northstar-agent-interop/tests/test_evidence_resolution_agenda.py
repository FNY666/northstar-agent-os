"""Tests for non-executing evidence resolution agendas."""
from __future__ import annotations

import unittest

from plan_evidence_decision import EvidencePlanStep, EvidencePlanManifest
from evidence_resolution_agenda import (
    AgendaError,
    AgendaVerification,
    EvidenceResolutionAgenda,
    ResolutionItem,
    make_resolution_agenda,
    verify_resolution_agenda,
)
from evidence_state_projection import ClaimProjection, SCHEMA as PROJECTION_SCHEMA
from plan_evidence_decision import make_plan_evidence_decision

D = lambda char: "sha256:" + char * 64


def projection(claim, *, state="supported", reason=(), unverified=()):
    if state == "unknown":
        return ClaimProjection(PROJECTION_SCHEMA, claim, state, False, (), (), (), tuple(sorted(reason)), tuple(sorted(unverified)))
    return ClaimProjection(
        PROJECTION_SCHEMA, claim, state, state == "supported",
        (D("c"),), (D("d"),), (D("e"),) if state == "conflicted" else (),
        tuple(sorted(reason)), tuple(sorted(unverified)),
    )


def manifest(*claims):
    return EvidencePlanManifest(
        "northstar.evidence-plan-manifest.v1",
        tuple(EvidencePlanStep("step-%d" % index, claim, "claim evidence") for index, claim in enumerate(claims)),
    )


def decision(*pairs):
    plan = manifest(*(claim for claim, _ in pairs))
    return make_plan_evidence_decision(plan, {claim: value for claim, value in pairs})


class AgendaCreationTests(unittest.TestCase):
    def test_conflict_becomes_escalate_conflict(self):
        claim = D("a")
        source = decision((claim, projection(claim, state="conflicted", reason=("root_mismatch",))))
        agenda = make_resolution_agenda(source)
        self.assertEqual(agenda.decision_state, "blocked")
        self.assertEqual(len(agenda.items), 1)
        item = agenda.items[0]
        self.assertEqual(item.claim_digest, claim)
        self.assertEqual(item.disposition, "escalate-conflict")
        self.assertEqual(item.evidence_state, "conflicted")
        self.assertIn("root_mismatch", item.reasons)
        self.assertFalse(agenda.execution_authorized)
        self.assertFalse(item.execution_authorized)

    def test_insufficient_and_unverifiable_become_reacquire_evidence(self):
        first, second = D("a"), D("b")
        source = decision(
            (first, projection(first, state="insufficient", reason=("policy_missing",))),
            (second, projection(second, state="unverifiable", reason=("pin_missing",))),
        )
        agenda = make_resolution_agenda(source)
        self.assertEqual(agenda.decision_state, "blocked")
        self.assertEqual([item.disposition for item in agenda.items], ["reacquire-evidence", "reacquire-evidence"])
        self.assertEqual([item.claim_digest for item in agenda.items], [first, second])

    def test_unknown_and_missing_claims_become_collect_evidence(self):
        known, missing = D("a"), D("b")
        plan = manifest(known, missing)
        source = make_plan_evidence_decision(plan, {known: projection(known, state="unknown", reason=("no_witness",))})
        agenda = make_resolution_agenda(source)
        self.assertEqual(agenda.decision_state, "unknown")
        self.assertEqual([item.disposition for item in agenda.items], ["collect-evidence", "collect-evidence"])
        by_claim = {item.claim_digest: item for item in agenda.items}
        self.assertEqual(by_claim[known].evidence_state, "unknown")
        self.assertEqual(by_claim[missing].evidence_state, "missing")
        self.assertIn("missing_claim_projection", by_claim[missing].reasons)

    def test_canonical_severity_order_is_not_a_winner_order(self):
        conflict, insufficient, unknown = D("c"), D("a"), D("b")
        source = decision(
            (conflict, projection(conflict, state="conflicted", reason=("conflict",))),
            (insufficient, projection(insufficient, state="insufficient", reason=("insufficient",))),
            (unknown, projection(unknown, state="unknown", reason=("unknown",))),
        )
        agenda = make_resolution_agenda(source)
        self.assertEqual(
            [item.disposition for item in agenda.items],
            ["escalate-conflict", "reacquire-evidence", "collect-evidence"],
        )
        self.assertEqual(agenda.items[0].claim_digest, conflict)

    def test_ready_decision_needs_no_resolution_agenda(self):
        claim = D("a")
        with self.assertRaises(AgendaError):
            make_resolution_agenda(decision((claim, projection(claim))))

    def test_wire_form_is_strict_and_has_no_raw_actions(self):
        claim = D("a")
        agenda = make_resolution_agenda(decision((claim, projection(claim, state="insufficient", reason=("missing",)))))
        self.assertEqual(EvidenceResolutionAgenda.from_dict(agenda.to_dict()), agenda)
        with self.assertRaises(AgendaError):
            EvidenceResolutionAgenda.from_dict({**agenda.to_dict(), "extra": True})
        rendered = str(agenda.to_dict())
        for forbidden in ("prompt", "command", "action", "event_id", "secret"):
            self.assertNotIn(forbidden, rendered)


class AgendaReplayTests(unittest.TestCase):
    def setUp(self):
        self.claim = D("a")
        self.source = decision((self.claim, projection(self.claim, state="conflicted", reason=("root_mismatch",), unverified=("same-key",))))
        self.agenda = make_resolution_agenda(self.source)

    def verify(self, agenda=None, **updates):
        agenda = self.agenda if agenda is None else agenda
        options = dict(
            agenda=agenda,
            decision=self.source,
            expected_agenda_digest=agenda.agenda_digest,
            expected_decision_digest=self.source.decision_digest,
        )
        options.update(updates)
        return verify_resolution_agenda(**options)

    def test_pinned_agenda_replays_without_execution_authority(self):
        verdict = self.verify()
        self.assertIsInstance(verdict, AgendaVerification)
        self.assertEqual(verdict.state, "agenda-verified")
        self.assertEqual(verdict.claimed_decision_state, "blocked")
        self.assertFalse(verdict.execution_authorized)
        self.assertIn("same-key", verdict.unverified)

    def test_missing_external_pins_are_explicit(self):
        verdict = self.verify(expected_agenda_digest=None, expected_decision_digest=None)
        self.assertEqual(verdict.state, "agenda-verified-unpinned")
        self.assertIn("agenda_digest_unpinned", verdict.unverified)
        self.assertIn("decision_digest_unpinned", verdict.unverified)

    def test_tampered_item_decision_or_digest_is_rejected(self):
        item = self.agenda.items[0]
        forged_item = ResolutionItem(item.claim_digest, "collect-evidence", item.evidence_state, item.reasons, item.unverified, False)
        forged = EvidenceResolutionAgenda(
            self.agenda.schema_version, self.agenda.plan_id,
            self.agenda.decision_digest, self.agenda.decision_state,
            (forged_item,), self.agenda.execution_authorized,
            self.agenda.agenda_digest,
        )
        with self.assertRaises(AgendaError):
            self.verify(forged)
        forged = EvidenceResolutionAgenda(
            self.agenda.schema_version, self.agenda.plan_id,
            D("f"), self.agenda.decision_state, self.agenda.items,
            self.agenda.execution_authorized, self.agenda.agenda_digest,
        )
        with self.assertRaises(AgendaError):
            self.verify(forged)
        with self.assertRaises(AgendaError):
            self.verify(expected_agenda_digest=D("e"))

    def test_changed_decision_is_rejected(self):
        changed = decision((self.claim, projection(self.claim, state="supported")))
        with self.assertRaises(AgendaError):
            verify_resolution_agenda(
                self.agenda, changed,
                expected_agenda_digest=self.agenda.agenda_digest,
                expected_decision_digest=self.source.decision_digest,
            )


if __name__ == "__main__":
    unittest.main()
