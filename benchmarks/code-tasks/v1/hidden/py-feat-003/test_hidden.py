import unittest
from unittest.mock import patch
from jsonl_summary import summarize


class ContractTests(unittest.TestCase):
    def test_early_validation(self):
        def source():
            yield "broken"
            raise AssertionError("preloaded beyond the invalid record")
        with self.assertRaisesRegex(ValueError, "line 1"):
            summarize(source())

    def test_physical_lines(self):
        with self.assertRaisesRegex(ValueError, "line 3"):
            summarize(["", " ", '{"value":false}'])

    def test_one_pass(self):
        class SinglePass:
            def __init__(self):
                self.used = False
            def __iter__(self):
                if self.used:
                    raise AssertionError("iterated twice")
                self.used = True
                yield '{"value":-1}'
        self.assertEqual(summarize(SinglePass()), {"records": 1, "total": -1})


if __name__ == "__main__":
    unittest.main()
