import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import live_run  # noqa: E402


class LiveRunDefaultsTests(unittest.TestCase):
    def test_live_run_defaults_are_safe_for_low_credit_reasoning_gateways(self):
        parser = live_run.build_parser()
        args = parser.parse_args(
            [
                "--fixture", "fixture.json",
                "--endpoint", "https://planner.example/v1/chat/completions",
                "--key-env", "TEST_PLANNER_API_KEY",
                "--model", "fixture/model",
                "--sandbox", "/tmp/live",
            ]
        )
        self.assertEqual(args.max_output_tokens, 2048)
        self.assertEqual(args.reasoning, "off")

    def test_explicit_budget_and_reasoning_can_still_be_overridden(self):
        parser = live_run.build_parser()
        args = parser.parse_args(
            [
                "--fixture", "fixture.json",
                "--endpoint", "https://planner.example/v1/chat/completions",
                "--key-env", "TEST_PLANNER_API_KEY",
                "--model", "fixture/model",
                "--sandbox", "/tmp/live",
                "--max-output-tokens", "512",
                "--reasoning", "low",
            ]
        )
        self.assertEqual(args.max_output_tokens, 512)
        self.assertEqual(args.reasoning, "low")
    def test_main_parses_arguments_before_loading_the_fixture(self):
        with self.assertRaises(FileNotFoundError):
            live_run.main(
                [
                    "--fixture", "/tmp/fixture-that-does-not-exist.json",
                    "--endpoint", "https://planner.example/v1/chat/completions",
                    "--key-env", "TEST_PLANNER_API_KEY",
                    "--model", "fixture/model",
                    "--sandbox", "/tmp/live",
                ]
            )


if __name__ == "__main__":
    unittest.main()
