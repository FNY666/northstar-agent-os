"""Tests for memory_fact_belief: fact/belief + privilege-at-recall."""
import unittest

from memory_fact_belief import (
    BELIEF_RECALL_THRESHOLD,
    MEMORY_FACT_BELIEF_VERSION,
    MemoryEntry,
    MemoryType,
    PrivilegeLevel,
    recall,
)


def make_fact(privilege=PrivilegeLevel.PRIVATE, content="user's name is X"):
    return MemoryEntry(
        content=content,
        type=MemoryType.FACT,
        confidence=1.0,
        source="onboarding",
        privilege=privilege,
    )


def make_belief(confidence=0.8, privilege=PrivilegeLevel.PUBLIC):
    return MemoryEntry(
        content="user probably likes Y",
        type=MemoryType.BELIEF,
        confidence=confidence,
        source="inference",
        privilege=privilege,
    )


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(MEMORY_FACT_BELIEF_VERSION, "memory-fact-belief.v1")

    def test_privilege_ordering(self):
        self.assertLess(PrivilegeLevel.PUBLIC, PrivilegeLevel.PRIVATE)
        self.assertLess(PrivilegeLevel.PRIVATE, PrivilegeLevel.SECRET)

    def test_memory_type_values(self):
        self.assertEqual(MemoryType.FACT.value, "fact")
        self.assertEqual(MemoryType.BELIEF.value, "belief")


class TestConstruction(unittest.TestCase):
    def test_fact_confidence_1(self):
        e = make_fact()
        self.assertEqual(e.confidence, 1.0)

    def test_fact_confidence_099_rejected(self):
        with self.assertRaises(ValueError):
            MemoryEntry(
                content="x",
                type=MemoryType.FACT,
                confidence=0.99,
                source="s",
                privilege=PrivilegeLevel.PUBLIC,
            )

    def test_fact_confidence_zero_rejected(self):
        with self.assertRaises(ValueError):
            MemoryEntry(
                content="x",
                type=MemoryType.FACT,
                confidence=0.0,
                source="s",
                privilege=PrivilegeLevel.PUBLIC,
            )

    def test_belief_confidence_bounds(self):
        self.assertEqual(make_belief(confidence=0.0).confidence, 0.0)
        self.assertEqual(make_belief(confidence=1.0).confidence, 1.0)

    def test_belief_confidence_over_one_rejected(self):
        with self.assertRaises(ValueError):
            make_belief(confidence=1.1)

    def test_belief_confidence_negative_rejected(self):
        with self.assertRaises(ValueError):
            make_belief(confidence=-0.1)

    def test_belief_confidence_nan_rejected(self):
        with self.assertRaises(ValueError):
            make_belief(confidence=float("nan"))

    def test_belief_confidence_bool_rejected(self):
        with self.assertRaises(TypeError):
            make_belief(confidence=True)

    def test_empty_content_rejected(self):
        with self.assertRaises(ValueError):
            MemoryEntry(
                content="",
                type=MemoryType.FACT,
                confidence=1.0,
                source="s",
                privilege=PrivilegeLevel.PUBLIC,
            )

    def test_empty_source_rejected(self):
        with self.assertRaises(ValueError):
            MemoryEntry(
                content="x",
                type=MemoryType.FACT,
                confidence=1.0,
                source="",
                privilege=PrivilegeLevel.PUBLIC,
            )

    def test_bad_privilege_rejected(self):
        with self.assertRaises(TypeError):
            MemoryEntry(
                content="x",
                type=MemoryType.FACT,
                confidence=1.0,
                source="s",
                privilege="PUBLIC",
            )

    def test_frozen(self):
        e = make_fact()
        with self.assertRaises(AttributeError):
            e.content = "changed"  # type: ignore


class TestRecallPrivilege(unittest.TestCase):
    def test_fact_equal_privilege_allowed(self):
        self.assertTrue(recall(make_fact(PrivilegeLevel.PRIVATE), PrivilegeLevel.PRIVATE))

    def test_fact_higher_reader_allowed(self):
        self.assertTrue(recall(make_fact(PrivilegeLevel.PUBLIC), PrivilegeLevel.SECRET))

    def test_fact_lower_reader_denied(self):
        self.assertFalse(recall(make_fact(PrivilegeLevel.SECRET), PrivilegeLevel.PRIVATE))

    def test_fact_public_to_public_allowed(self):
        self.assertTrue(recall(make_fact(PrivilegeLevel.PUBLIC), PrivilegeLevel.PUBLIC))

    def test_fact_secret_to_secret_allowed(self):
        self.assertTrue(recall(make_fact(PrivilegeLevel.SECRET), PrivilegeLevel.SECRET))

    def test_fact_public_to_private_denied_reverse(self):
        # reader below entry privilege is denied even at the low end
        self.assertFalse(recall(make_fact(PrivilegeLevel.PRIVATE), PrivilegeLevel.PUBLIC))


class TestRecallBeliefThreshold(unittest.TestCase):
    def test_threshold_value(self):
        self.assertEqual(BELIEF_RECALL_THRESHOLD, 0.7)

    def test_belief_at_threshold_allowed(self):
        self.assertTrue(recall(make_belief(confidence=0.7), PrivilegeLevel.PUBLIC))

    def test_belief_above_threshold_allowed(self):
        self.assertTrue(recall(make_belief(confidence=0.9), PrivilegeLevel.PUBLIC))

    def test_belief_below_threshold_denied_even_for_secret(self):
        self.assertFalse(recall(make_belief(confidence=0.69), PrivilegeLevel.SECRET))

    def test_belief_zero_confidence_denied(self):
        self.assertFalse(recall(make_belief(confidence=0.0), PrivilegeLevel.SECRET))

    def test_belief_threshold_and_privilege_both_checked(self):
        # high confidence but insufficient privilege -> denied
        self.assertFalse(recall(make_belief(confidence=0.95, privilege=PrivilegeLevel.SECRET), PrivilegeLevel.PUBLIC))
        # sufficient privilege but low confidence -> denied
        self.assertFalse(recall(make_belief(confidence=0.5, privilege=PrivilegeLevel.PUBLIC), PrivilegeLevel.SECRET))


class TestRecallMalformed(unittest.TestCase):
    def test_invalid_reader_privilege_raises(self):
        with self.assertRaises(TypeError):
            recall(make_fact(), "PRIVATE")  # type: ignore

    def test_invalid_entry_raises(self):
        with self.assertRaises(TypeError):
            recall("not-an-entry", PrivilegeLevel.PUBLIC)  # type: ignore


class TestHelpers(unittest.TestCase):
    def test_is_belief_below_threshold_fact_false(self):
        self.assertFalse(make_fact().is_belief_below_threshold())

    def test_is_belief_below_threshold_strong_belief_false(self):
        self.assertFalse(make_belief(confidence=0.7).is_belief_below_threshold())

    def test_is_belief_below_threshold_weak_belief_true(self):
        self.assertTrue(make_belief(confidence=0.69).is_belief_below_threshold())

    def test_main_smoke(self):
        import memory_fact_belief

        memory_fact_belief.main()


if __name__ == "__main__":
    unittest.main()
