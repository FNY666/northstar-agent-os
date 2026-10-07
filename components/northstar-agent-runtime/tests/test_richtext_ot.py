"""Tests for richtext_ot: operational transform op bookkeeping."""

import ast
import random
import threading
import unittest

from richtext_ot import (
    SCHEMA,
    VERSION,
    ApplyReport,
    BadSideError,
    OpComponent,
    OpLengthError,
    OpShapeError,
    OTError,
    RichTextOT,
    SeqOrderError,
    TextOp,
    compose_components,
    main,
    richtext_ot_audit_event,
    transform_components,
)


def R(n, attrs=None):
    d = {"kind": "retain", "length": n}
    if attrs:
        d["attributes"] = attrs
    return d


def I(text, attrs=None):
    d = {"kind": "insert", "text": text}
    if attrs:
        d["attributes"] = attrs
    return d


def D(n):
    return {"kind": "delete", "length": n}


def apply_dicts(doc, op, seq):
    """Apply a TextOp given as components; helper for transform results."""
    return doc.apply(
        [{"kind": c.kind,
          **({"text": c.text} if c.kind == "insert" else {"length": c.length}),
          **({"attributes": dict(c.attrs)} if c.attrs else {})}
         for c in op.components], seq)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(VERSION, "richtext-ot.v1")
        self.assertEqual(SCHEMA, "northstar.richtext-ot.v1")
        doc = RichTextOT("ab")
        rep = doc.apply([R(2)], seq=1)
        self.assertTrue(rep.op.digest.startswith("sha256:"))
        self.assertEqual(rep.op.as_dict()["schema"], SCHEMA)


class TestApply(unittest.TestCase):
    def test_insert_happy_path(self):
        doc = RichTextOT("hello")
        rep = doc.apply([R(5), I(" world")], seq=1)
        self.assertIsInstance(rep, ApplyReport)
        self.assertEqual(rep.text, "hello world")
        self.assertEqual(doc.text(), "hello world")
        self.assertEqual(rep.op.op_id, "op-1")
        self.assertEqual(doc.version, 1)
        self.assertEqual(rep.prev_digest, "genesis")
        self.assertTrue(rep.op.digest.startswith("sha256:"))

    def test_retain_delete(self):
        doc = RichTextOT("abcdef")
        doc.apply([R(1), D(2), R(3)], seq=1)
        self.assertEqual(doc.text(), "adef")

    def test_digest_chain(self):
        doc = RichTextOT("ab")
        r1 = doc.apply([R(2)], seq=1)
        r2 = doc.apply([R(2)], seq=2)
        self.assertEqual(r2.prev_digest, r1.op.digest)
        hist = doc.history()
        self.assertEqual([h["op_id"] for h in hist], ["op-1", "op-2"])
        self.assertEqual(hist[1]["prev_digest"], hist[0]["digest"])

    def test_length_mismatch(self):
        doc = RichTextOT("abc")
        with self.assertRaises(OpLengthError):
            doc.apply([R(2)], seq=1)  # too short
        with self.assertRaises(OpLengthError):
            doc.apply([R(4)], seq=1)  # too long
        with self.assertRaises(OpLengthError):
            doc.apply([I("x")], seq=1)  # consumes nothing

    def test_seq_order(self):
        doc = RichTextOT("ab")
        doc.apply([R(2)], seq=1)
        with self.assertRaises(SeqOrderError):
            doc.apply([R(2)], seq=1)
        with self.assertRaises(SeqOrderError):
            doc.apply([R(2)], seq=0)
        with self.assertRaises(OTError):
            doc.apply([R(2)], seq=True)
        with self.assertRaises(OTError):
            doc.apply([R(2)], seq="1")

    def test_shape_errors(self):
        doc = RichTextOT("ab")
        bad_ops = [
            [{"kind": "splice", "length": 2}],          # unknown kind
            [{"kind": "retain", "length": 0}],          # zero length
            [{"kind": "delete", "length": -1}],         # negative
            [{"kind": "retain", "length": True}],      # bool length
            [{"kind": "insert", "text": ""}],          # empty insert
            [{"kind": "insert", "text": 5}],           # non-str text
            [{"kind": "retain", "length": 2, "text": "x"}],  # stray text
            [{"kind": "retain", "length": 2,
              "attributes": {"bold": 5}}],             # bad attr value
            [{"kind": "retain", "length": 2,
              "attributes": ["bold"]}],                # bad attr shape
            ["not-a-component"],
        ]
        seq = 1
        for op in bad_ops:
            with self.assertRaises(OpShapeError, msg=str(op)):
                doc.apply(op, seq=seq)

    def test_empty_op_is_noop(self):
        # transform can legitimately yield an empty op (e.g. retain vs
        # delete-all); it applies as a no-op to the resulting empty doc.
        doc = RichTextOT("")
        rep = doc.apply([], seq=1)
        self.assertEqual(rep.text, "")
        self.assertEqual(rep.op.components, ())
        with self.assertRaises(OpLengthError):
            RichTextOT("ab").apply([], seq=1)

    def test_normalize_merges_adjacent(self):
        doc = RichTextOT("abcd")
        rep = doc.apply([R(1), R(1), I("x"), I("y"), R(2)], seq=1)
        kinds = [(c.kind, c.text or c.length) for c in rep.op.components]
        self.assertEqual(kinds, [("retain", 2), ("insert", "xy"),
                                ("retain", 2)])
        self.assertEqual(doc.text(), "abxycd")


class TestTransform(unittest.TestCase):
    def test_insert_insert_tiebreak(self):
        # both insert at position 1 of "ab"
        a = [R(1), I("X"), R(1)]
        b = [R(1), I("Y"), R(1)]
        doc = RichTextOT("ab")
        a_left = doc.transform(a, b, seq=1, side="left")
        b_right = doc.transform(b, a, seq=2, side="right")
        ldoc = RichTextOT("ab")
        ldoc.apply(b, seq=1)
        apply_dicts(ldoc, a_left, seq=2)
        rdoc = RichTextOT("ab")
        rdoc.apply(a, seq=1)
        apply_dicts(rdoc, b_right, seq=2)
        self.assertEqual(ldoc.text(), "aXYb")   # a first with side=left
        self.assertEqual(rdoc.text(), "aXYb")   # consistent: a first
        # flipped: b priority
        a_right = doc.transform(a, b, seq=3, side="right")
        b_left = doc.transform(b, a, seq=4, side="left")
        ldoc2 = RichTextOT("ab")
        ldoc2.apply(b, seq=1)
        apply_dicts(ldoc2, a_right, seq=2)
        rdoc2 = RichTextOT("ab")
        rdoc2.apply(a, seq=1)
        apply_dicts(rdoc2, b_left, seq=2)
        self.assertEqual(ldoc2.text(), "aYXb")
        self.assertEqual(rdoc2.text(), "aYXb")

    def test_bad_side(self):
        doc = RichTextOT("ab")
        a = [R(2)]
        b = [R(2)]
        with self.assertRaises(BadSideError):
            doc.transform(a, b, seq=1, side="middle")

    def test_delete_vs_retain(self):
        doc = RichTextOT("abcd")
        a = [D(2), R(2)]   # delete "ab"
        b = [R(4)]         # noop
        a_prime = doc.transform(a, b, seq=1, side="left")
        kinds = [(c.kind, c.length) for c in a_prime.components]
        self.assertEqual(kinds, [("delete", 2), ("retain", 2)])

    def test_delete_delete_idempotent(self):
        # both delete the same 2 chars: transformed op is empty-ish
        doc = RichTextOT("abcd")
        a = [D(2), R(2)]
        b = [D(2), R(2)]
        a_prime = doc.transform(a, b, seq=1, side="left")
        ldoc = RichTextOT("abcd")
        ldoc.apply(b, seq=1)
        apply_dicts(ldoc, a_prime, seq=2)
        self.assertEqual(ldoc.text(), "cd")

    def test_insert_vs_delete_survives(self):
        doc = RichTextOT("ab")
        a = [I("X"), R(2)]       # insert at 0
        b = [D(1), R(1)]         # delete 'a'
        a_prime = doc.transform(a, b, seq=1, side="left")
        ldoc = RichTextOT("ab")
        ldoc.apply(b, seq=1)     # "b"
        apply_dicts(ldoc, a_prime, seq=2)
        self.assertEqual(ldoc.text(), "Xb")

    def test_delete_shifts_past_insert(self):
        # regression: T(del, ins) must shift the delete past b's insert
        doc = RichTextOT("ab")
        a = [D(1), R(1)]              # delete 'a'
        b = [I(">>"), R(2)]           # insert at 0
        b_prime = doc.transform(b, a, seq=1, side="right")
        kinds = [(c.kind, c.text or c.length) for c in b_prime.components]
        # b's insert passes through a's delete unaffected; the delete
        # only consumes one retain of b's.
        self.assertEqual(kinds, [("insert", ">>"), ("retain", 1)])
        rdoc = RichTextOT("ab")
        rdoc.apply(a, seq=1)          # "b"
        apply_dicts(rdoc, b_prime, seq=2)
        self.assertEqual(rdoc.text(), ">>b")
        # and the mirror direction shifts the delete past the insert
        a_prime = doc.transform(a, b, seq=2, side="left")
        kinds_a = [(c.kind, c.text or c.length)
                   for c in a_prime.components]
        self.assertEqual(kinds_a, [("retain", 2), ("delete", 1),
                                  ("retain", 1)])
        ldoc = RichTextOT("ab")
        ldoc.apply(b, seq=1)          # ">>ab"
        apply_dicts(ldoc, a_prime, seq=2)
        self.assertEqual(ldoc.text(), ">>b")

    def test_pair_length_mismatch(self):
        doc = RichTextOT("abc")
        with self.assertRaises(OpLengthError):
            doc.transform([R(3)], [R(2)], seq=1, side="left")

    def test_tp1_convergence_property(self):
        rnd = random.Random(20261007)
        alphabet = "abcd"
        for trial in range(60):
            n = rnd.randint(0, 6)
            text = "".join(rnd.choice(alphabet) for _ in range(n))

            def rand_op(length):
                comps = []
                remaining = length
                while remaining > 0 or (comps and rnd.random() < 0.3):
                    r = rnd.random()
                    if r < 0.25:
                        comps.append(I("".join(
                            rnd.choice(alphabet)
                            for _ in range(rnd.randint(1, 2)))))
                    elif remaining > 0 and r < 0.6:
                        k = rnd.randint(1, remaining)
                        comps.append(R(k))
                        remaining -= k
                    elif remaining > 0:
                        k = rnd.randint(1, remaining)
                        comps.append(D(k))
                        remaining -= k
                    else:
                        break
                if not comps:
                    comps.append(I("z"))
                return comps

            a = rand_op(n)
            b = rand_op(n)
            doc = RichTextOT("seed")
            a_prime = doc.transform(a, b, seq=1, side="left")
            b_prime = doc.transform(b, a, seq=2, side="right")
            left = RichTextOT(text)
            left.apply(b, seq=1)
            apply_dicts(left, a_prime, seq=2)
            right = RichTextOT(text)
            right.apply(a, seq=1)
            apply_dicts(right, b_prime, seq=2)
            self.assertEqual(left.text(), right.text(),
                             f"trial {trial}: text diverged\na={a}\nb={b}")
            self.assertEqual(left.segments(), right.segments(),
                             f"trial {trial}: attrs diverged\na={a}\nb={b}")


class TestCompose(unittest.TestCase):
    def test_compose_equivalence(self):
        d1 = RichTextOT("abc")
        op1 = [R(1), I("X"), R(2)]
        op2 = [R(2), D(1), R(1)]
        d1.apply(op1, seq=1)
        d1.apply(op2, seq=2)
        doc = RichTextOT("seed")
        composed = doc.compose(op1, op2, seq=3)
        d2 = RichTextOT("abc")
        apply_dicts(d2, composed, seq=1)
        self.assertEqual(d1.text(), d2.text())
        self.assertEqual(d1.text(), "aXc")

    def test_compose_insert_delete_cancel(self):
        comps = compose_components([I("hello")], [D(5)])
        self.assertEqual(list(comps), [])

    def test_compose_length_mismatch(self):
        doc = RichTextOT("ab")
        with self.assertRaises(OpLengthError):
            doc.compose([R(2)], [R(3)], seq=1)

    def test_compose_attr_merge_later_wins(self):
        doc = RichTextOT("seed")
        comps = compose_components(
            [R(1, {"bold": "true", "color": "red"})],
            [R(1, {"color": "blue"})])
        self.assertEqual(len(comps), 1)
        self.assertEqual(dict(comps[0].attrs),
                         {"bold": "true", "color": "blue"})

    def test_compose_property(self):
        rnd = random.Random(77)
        alphabet = "abcd"
        for trial in range(40):
            n = rnd.randint(0, 6)
            text = "".join(rnd.choice(alphabet) for _ in range(n))

            def rand_consume(length):
                comps, remaining = [], length
                while remaining > 0:
                    r = rnd.random()
                    if r < 0.4:
                        k = rnd.randint(1, remaining)
                        comps.append(R(k))
                        remaining -= k
                    elif r < 0.7:
                        comps.append(I("".join(
                            rnd.choice(alphabet)
                            for _ in range(rnd.randint(1, 2)))))
                    else:
                        k = rnd.randint(1, remaining)
                        comps.append(D(k))
                        remaining -= k
                return comps or [I("q")]

            a = rand_consume(n)
            d1 = RichTextOT(text)
            d1.apply(a, seq=1)
            b = rand_consume(len(d1.text()))
            d1.apply(b, seq=2)
            doc = RichTextOT("seed")
            composed = doc.compose(a, b, seq=3)
            d2 = RichTextOT(text)
            apply_dicts(d2, composed, seq=1)
            self.assertEqual(d1.text(), d2.text(),
                             f"trial {trial}\na={a}\nb={b}")


class TestAttributes(unittest.TestCase):
    def test_retain_applies_attrs(self):
        doc = RichTextOT("hi")
        doc.apply([R(2, {"bold": "true"})], seq=1)
        self.assertEqual(doc.char_attrs(0), {"bold": "true"})
        self.assertEqual(doc.segments(),
                         [{"text": "hi", "attrs": {"bold": "true"}}])

    def test_attr_removal_with_none(self):
        doc = RichTextOT("hi", attrs={"bold": "true"})
        doc.apply([R(1), R(1, {"bold": None})], seq=1)
        self.assertEqual(doc.char_attrs(0), {"bold": "true"})
        self.assertEqual(doc.char_attrs(1), {})

    def test_insert_carries_attrs(self):
        doc = RichTextOT("ab")
        doc.apply([R(1), I("X", {"italic": "true"}), R(1)], seq=1)
        self.assertEqual(doc.segments(), [
            {"text": "a", "attrs": {}},
            {"text": "X", "attrs": {"italic": "true"}},
            {"text": "b", "attrs": {}},
        ])

    def test_attr_conflict_transform_sides(self):
        doc = RichTextOT("ab")
        a = [R(2, {"color": "red"})]
        b = [R(2, {"color": "blue"})]
        a_left = doc.transform(a, b, seq=1, side="left")
        self.assertEqual(dict(a_left.components[0].attrs), {"color": "red"})
        a_right = doc.transform(a, b, seq=2, side="right")
        self.assertEqual(dict(a_right.components[0].attrs), {"color": "blue"})
        # and the pair still converges
        b_right = doc.transform(b, a, seq=3, side="right")
        b_left = doc.transform(b, a, seq=4, side="left")
        ldoc = RichTextOT("ab")
        ldoc.apply(b, seq=1)
        apply_dicts(ldoc, a_left, seq=2)
        rdoc = RichTextOT("ab")
        rdoc.apply(a, seq=1)
        apply_dicts(rdoc, b_right, seq=2)
        self.assertEqual(ldoc.segments(), rdoc.segments())
        self.assertEqual(ldoc.segments()[0]["attrs"], {"color": "red"})
        ldoc2 = RichTextOT("ab")
        ldoc2.apply(b, seq=1)
        apply_dicts(ldoc2, a_right, seq=2)
        rdoc2 = RichTextOT("ab")
        rdoc2.apply(a, seq=1)
        apply_dicts(rdoc2, b_left, seq=2)
        self.assertEqual(ldoc2.segments(), rdoc2.segments())
        self.assertEqual(ldoc2.segments()[0]["attrs"], {"color": "blue"})


class TestAuditAndMeta(unittest.TestCase):
    def test_audit_shapes(self):
        doc = RichTextOT("ab")
        rep = doc.apply([R(2)], seq=1)
        ev = richtext_ot_audit_event("applied", doc, op=rep.op)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "applied")
        self.assertEqual(ev["op_id"], "op-1")
        self.assertEqual(ev["digest"], rep.op.digest)
        self.assertEqual(ev["version"], VERSION)
        ev2 = richtext_ot_audit_event("rejected", doc, reason="bad-op")
        self.assertEqual(ev2["reason"], "bad-op")
        with self.assertRaises(OTError):
            richtext_ot_audit_event("bogus", doc)

    def test_stdlib_only(self):
        import richtext_ot as m
        with open(m.__file__) as f:
            src = f.read()
        tree = ast.parse(src)
        allowed = {"hashlib", "threading", "dataclasses", "typing",
                   "__future__", "json", "canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed,
                              node.module)

    def test_main(self):
        self.assertEqual(main(), 0)

    def test_thread_safety(self):
        doc = RichTextOT("x" * 10)
        errors = []

        def worker(k):
            try:
                for s in range(1, 6):
                    doc.apply([R(10)], seq=1000 * k + s)
            except Exception as e:  # noqa: BLE001 - collecting only
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(k,))
                   for k in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # seqs interleave across threads so some must fail closed;
        # the document itself must stay consistent.
        self.assertEqual(doc.text(), "x" * 10)
        self.assertTrue(all(isinstance(e, SeqOrderError) for e in errors))


if __name__ == "__main__":
    unittest.main()
