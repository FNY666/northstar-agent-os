"""Tests for hash_chain.py: append-only tamper-evident ordering."""

import unittest

from hash_chain import (
    ChainLink,
    ChainVerificationError,
    HashChain,
    HashChainError,
    HASH_CHAIN_SCHEMA,
    HASH_CHAIN_VERSION,
    _GENESIS,
    hash_chain_audit_event,
)


def _tampered(chain, seq, **overrides):
    evil = HashChain()
    links = []
    for link in chain.links():
        vals = {
            "seq": link.seq,
            "data_digest": link.data_digest,
            "prev_hash": link.prev_hash,
            "link_hash": link.link_hash,
        }
        if link.seq == seq:
            vals.update(overrides)
        links.append(ChainLink(**vals))
    evil._links = links
    return evil


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(HASH_CHAIN_VERSION, "hash-chain.v1")

    def test_schema_pin(self):
        self.assertEqual(HASH_CHAIN_SCHEMA, "northstar.hash-chain.v1")


class TestAppend(unittest.TestCase):
    def test_empty_chain_verify(self):
        chain = HashChain()
        self.assertEqual(len(chain), 0)
        self.assertIsNone(chain.head())
        self.assertEqual(chain.head_digest(), _GENESIS)
        self.assertTrue(chain.verify())

    def test_append_returns_link(self):
        chain = HashChain()
        link = chain.append({"op": "put"}, 0)
        self.assertIsInstance(link, ChainLink)
        self.assertEqual(link.seq, 0)
        self.assertEqual(link.prev_hash, _GENESIS)
        self.assertTrue(link.link_hash.startswith("sha256:"))
        self.assertEqual(len(chain), 1)
        self.assertIs(chain.head(), link)

    def test_first_link_binds_genesis(self):
        c1, c2 = HashChain(), HashChain()
        l1 = c1.append("same", 0)
        l2 = c2.append("same", 0)
        self.assertEqual(l1.link_hash, l2.link_hash)

    def test_chain_links_previous(self):
        chain = HashChain()
        a = chain.append("a", 0)
        b = chain.append("b", 1)
        self.assertEqual(b.prev_hash, a.link_hash)
        self.assertEqual(chain.head_digest(), b.link_hash)

    def test_seq_gap_refused(self):
        chain = HashChain()
        chain.append("a", 0)
        with self.assertRaises(HashChainError):
            chain.append("b", 2)

    def test_seq_rewind_refused(self):
        chain = HashChain()
        chain.append("a", 0)
        with self.assertRaises(HashChainError):
            chain.append("b", 0)

    def test_seq_bool_refused(self):
        chain = HashChain()
        with self.assertRaises(HashChainError):
            chain.append("a", True)

    def test_non_canonicalizable_refused(self):
        chain = HashChain()
        with self.assertRaises(HashChainError):
            chain.append(object(), 0)

    def test_nan_refused(self):
        chain = HashChain()
        with self.assertRaises(HashChainError):
            chain.append(float("nan"), 0)

    def test_inf_refused(self):
        chain = HashChain()
        with self.assertRaises(HashChainError):
            chain.append(float("inf"), 0)

    def test_huge_integral_float_refused(self):
        chain = HashChain()
        with self.assertRaises(HashChainError):
            chain.append(2.0**54, 0)

    def test_non_str_mapping_keys_refused(self):
        chain = HashChain()
        with self.assertRaises(HashChainError):
            chain.append({1: "x"}, 0)


class TestCanonicalization(unittest.TestCase):
    def test_key_order_independent(self):
        c1, c2 = HashChain(), HashChain()
        c1.append({"b": 2, "a": 1}, 0)
        c2.append({"a": 1, "b": 2}, 0)
        self.assertEqual(c1.head_digest(), c2.head_digest())

    def test_type_tags_distinct(self):
        digests = set()
        for value in ("1", 1, b"1", 1.0, True, None, [1], {"v": 1}):
            c = HashChain()
            digests.add(c.append(value, 0).data_digest)
        self.assertEqual(len(digests), 8)

    def test_nested_structures(self):
        c1, c2 = HashChain(), HashChain()
        payload = {"ops": [{"k": "a", "v": [1, 2, {"n": None}]}, True]}
        l1 = c1.append(payload, 0)
        l2 = c2.append(payload, 0)
        self.assertEqual(l1.data_digest, l2.data_digest)

    def test_big_int_exact(self):
        c1, c2 = HashChain(), HashChain()
        big = 2**100 + 7
        self.assertEqual(
            c1.append(big, 0).data_digest, c2.append(big, 0).data_digest
        )


class TestVerify(unittest.TestCase):
    def _chain(self, n=4):
        chain = HashChain()
        for i in range(n):
            chain.append({"seq": i, "val": f"v{i}"}, i)
        return chain

    def test_verify_clean(self):
        chain = self._chain()
        self.assertTrue(chain.verify())
        chain.verify_strict()  # must not raise

    def test_tampered_data_detected(self):
        chain = self._chain()
        evil = _tampered(chain, 1, data_digest=chain.link(2).data_digest)
        self.assertFalse(evil.verify())
        with self.assertRaises(ChainVerificationError) as ctx:
            evil.verify_strict()
        self.assertEqual(ctx.exception.index, 1)

    def test_tampered_link_hash_detected(self):
        chain = self._chain()
        evil = _tampered(chain, 2, link_hash=chain.link(0).link_hash)
        self.assertFalse(evil.verify())
        with self.assertRaises(ChainVerificationError):
            evil.verify_strict()

    def test_broken_prev_link_detected(self):
        chain = self._chain()
        evil = _tampered(chain, 2, prev_hash=_GENESIS)
        self.assertFalse(evil.verify())

    def test_tamper_cascades(self):
        # changing an early payload breaks every later link's prev_hash
        chain = self._chain()
        evil = _tampered(chain, 0, data_digest=chain.link(3).data_digest)
        self.assertFalse(evil.verify())

    def test_empty_verify_strict_ok(self):
        HashChain().verify_strict()


class TestViews(unittest.TestCase):
    def test_links_tuple(self):
        chain = HashChain()
        chain.append("a", 0)
        chain.append("b", 1)
        links = chain.links()
        self.assertEqual(len(links), 2)
        self.assertEqual(links[0].seq, 0)

    def test_link_fetch(self):
        chain = HashChain()
        chain.append("a", 0)
        self.assertEqual(chain.link(0).data_digest, chain.head().data_digest)
        with self.assertRaises(IndexError):
            chain.link(5)

    def test_contains_data(self):
        chain = HashChain()
        chain.append({"k": "v"}, 0)
        self.assertTrue(chain.contains_data({"k": "v"}))
        self.assertFalse(chain.contains_data({"k": "other"}))
        self.assertFalse(HashChain().contains_data("x"))


class TestChainLinkRecord(unittest.TestCase):
    def test_frozen(self):
        link = ChainLink(
            seq=0,
            data_digest="sha256:" + "ab" * 32,
            prev_hash=_GENESIS,
            link_hash="sha256:" + "cd" * 32,
        )
        with self.assertRaises(Exception):
            link.seq = 9

    def test_bad_seq_rejected(self):
        kw = dict(
            data_digest="sha256:" + "ab" * 32,
            prev_hash=_GENESIS,
            link_hash="sha256:" + "cd" * 32,
        )
        with self.assertRaises(HashChainError):
            ChainLink(seq=True, **kw)
        with self.assertRaises(HashChainError):
            ChainLink(seq=-1, **kw)

    def test_bad_pin_rejected(self):
        with self.assertRaises(HashChainError):
            ChainLink(seq=0, data_digest="nope", prev_hash=_GENESIS,
                      link_hash="sha256:" + "cd" * 32)

    def test_as_dict_shape(self):
        chain = HashChain()
        d = chain.append("x", 0).as_dict()
        self.assertEqual(d["schema"], HASH_CHAIN_SCHEMA)
        self.assertEqual(d["version"], HASH_CHAIN_VERSION)
        self.assertEqual(d["seq"], 0)


class TestAuditEvent(unittest.TestCase):
    def test_shape(self):
        chain = HashChain()
        chain.append("a", 0)
        ev = hash_chain_audit_event("appended", chain, 7)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "hash-chain.appended")
        self.assertEqual(ev["module"], HASH_CHAIN_SCHEMA)
        self.assertEqual(ev["seq"], 7)
        self.assertEqual(ev["length"], 1)
        self.assertEqual(ev["head_digest"], chain.head_digest())

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            hash_chain_audit_event("nope", HashChain(), 0)

    def test_bad_seq(self):
        with self.assertRaises(ValueError):
            hash_chain_audit_event("verified", HashChain(), -1)
        with self.assertRaises(ValueError):
            hash_chain_audit_event("verified", HashChain(), True)

    def test_bad_chain(self):
        with self.assertRaises(TypeError):
            hash_chain_audit_event("verified", "not-a-chain", 0)

    def test_all_kinds(self):
        for kind in ("created", "appended", "verified", "verification-failed"):
            ev = hash_chain_audit_event(kind, HashChain(), 0)
            self.assertEqual(ev["kind"], f"hash-chain.{kind}")


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        from hash_chain import main
        main()


if __name__ == "__main__":
    unittest.main()
