"""Tests for aml_screener.py (simulated sanctions/watchlist screening)."""

import unittest

from aml_screener import (
    AMLScreener,
    BadSubjectError,
    DuplicateEntryError,
    InvalidTransitionError,
    UnknownHitError,
    UnknownListError,
    WatchlistEntry,
    normalize_name,
    similarity,
)

ENTRY = {
    "entry_id": "SDN-001",
    "primary_name": "John Alexander Smith",
    "aliases": ("J. A. Smith", "Jon Smyth"),
    "identifiers": ("P1234567",),
    "programs": ("OFAC-DPRK",),
    "risk": "critical",
}


def _screener():
    s = AMLScreener()
    s.load_watchlist("OFAC-SDN", [dict(ENTRY)])
    return s


class TestNormalization(unittest.TestCase):
    def test_normalize_folds_diacritics_and_case(self):
        self.assertEqual(normalize_name("  José  GARCÍA! "), "jose garcia")

    def test_similarity_identical_is_one(self):
        self.assertEqual(similarity("John Smith", "john smith"), 1.0)


class TestScreening(unittest.TestCase):
    def test_exact_name_match_becomes_open_hit(self):
        r = _screener().screen("John Alexander Smith")
        self.assertEqual(r.verdict, "potential-match")
        self.assertEqual(len(r.hits), 1)
        h = r.hits[0]
        self.assertEqual((h.match_kind, h.score, h.state),
                         ("exact", 1.0, "open"))

    def test_alias_match_is_alias_kind(self):
        r = _screener().screen("J. A. Smith")
        self.assertTrue(r.hits)
        self.assertEqual(r.hits[0].match_kind, "alias")

    def test_identifier_match_is_identifier_kind(self):
        r = _screener().screen("Totally Different", identifiers=("P1234567",))
        self.assertTrue(r.hits)
        self.assertEqual(r.hits[0].match_kind, "identifier")

    def test_fuzzy_match_above_threshold(self):
        r = _screener().screen("John Aleksander Smith")
        self.assertTrue(r.hits)
        self.assertEqual(r.hits[0].match_kind, "fuzzy")

    def test_clean_subject_returns_clear_verdict(self):
        r = _screener().screen("Maria Consuelo Garcia")
        self.assertEqual(r.verdict, "clear")
        self.assertEqual(r.hits, ())

    def test_threshold_filters_weak_matches(self):
        r = _screener().screen("John Aleksander Smith", threshold=1.0)
        self.assertEqual(r.verdict, "clear")


class TestDisposition(unittest.TestCase):
    def test_hit_confirms_true_positive(self):
        s = _screener()
        hid = s.screen("John Alexander Smith").hits[0].hit_id
        h = s.hit(hid, note="dob matches")
        self.assertEqual(h.state, "confirmed")
        self.assertEqual(h.note, "dob matches")
        self.assertEqual(s.open_hits(), ())

    def test_clear_releases_false_positive(self):
        s = _screener()
        hid = s.screen("John Aleksander Smith").hits[0].hit_id
        h = s.clear(hid, note="different dob")
        self.assertEqual(h.state, "cleared")

    def test_escalate_requires_human_review(self):
        s = _screener()
        hid = s.screen("John Alexander Smith").hits[0].hit_id
        h = s.escalate(hid, note="needs analyst")
        self.assertEqual(h.state, "escalated")

    def test_terminal_hit_cannot_transition(self):
        s = _screener()
        hid = s.screen("John Alexander Smith").hits[0].hit_id
        s.clear(hid)
        with self.assertRaises(InvalidTransitionError):
            s.hit(hid)

    def test_unknown_hit_id_raises(self):
        with self.assertRaises(UnknownHitError):
            _screener().hit("H-999999")


class TestErrors(unittest.TestCase):
    def test_load_unknown_watchlist_raises(self):
        with self.assertRaises(UnknownListError):
            AMLScreener().load_watchlist("Nope-List", [])

    def test_duplicate_entry_raises(self):
        s = _screener()
        with self.assertRaises(DuplicateEntryError):
            s.add_entry(WatchlistEntry(
                list_name="OFAC-SDN", entry_id="SDN-001",
                primary_name="Someone Else"))

    def test_blank_subject_raises(self):
        with self.assertRaises(BadSubjectError):
            _screener().screen("   ")


class TestAudit(unittest.TestCase):
    def test_history_and_audit_trail(self):
        s = _screener()
        hid = s.screen("John Alexander Smith").hits[0].hit_id
        s.hit(hid, note="x")
        h = s.get_hit(hid)
        self.assertEqual([t["to"] for t in h.history], ["open", "confirmed"])
        kinds = [e["kind"] for e in s.audit_log()]
        for k in ("watchlist-loaded", "screened", "hit"):
            self.assertIn(k, kinds)
        self.assertEqual(len(s.digest()), 64)


if __name__ == "__main__":
    unittest.main()
