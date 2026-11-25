"""Input-boundary tests for the SWE-bench sample archiver."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "freeze_swe_bench_sample", ROOT / "scripts" / "freeze_swe_bench_sample.py"
)
assert SPEC is not None and SPEC.loader is not None
FREEZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FREEZER)


class FreezeSweBenchInputTests(unittest.TestCase):
    def test_image_name_accepts_a_canonical_instance_id(self):
        self.assertEqual(
            FREEZER.image_name("pytest-dev/pytest", "8.0", "pytest-dev__pytest-10051"),
            "swebench/sweb.eval.x86_64.pytest-dev_1776_pytest-10051:latest",
        )
        self.assertEqual(
            FREEZER.image_name("ignored", "1", "org__repo__suffix-2"),
            "swebench/sweb.eval.x86_64.org_1776_repo__suffix-2:latest",
        )

    def test_image_name_rejects_path_and_url_delimiters(self):
        invalid_ids = (
            "../evil__repo-1",
            "org__repo?scope=repository:attacker:pull",
            "org__repo&scope=repository:attacker:pull",
            "org__repo/tag",
            "org__repo:tag",
            "org__",
        )
        for instance_id in invalid_ids:
            with self.subTest(instance_id=instance_id):
                with self.assertRaises(ValueError):
                    FREEZER.image_name("ignored", "1", instance_id)

    def test_noncanonical_image_is_rejected_before_any_network_request(self):
        with mock.patch.object(FREEZER.urllib.request, "urlopen") as urlopen:
            self.assertIsNone(FREEZER.image_digest("swebench/other:latest"))
            self.assertIsNone(FREEZER.image_digest("https://attacker.example/image:latest"))
        urlopen.assert_not_called()

    def test_registry_token_scope_is_one_encoded_query_parameter(self):
        repository = "swebench/sweb.eval.x86_64.good&scope=repository:attacker:pull"
        captured: list[str] = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self):
                return b'{"token":"stub-token"}'

        def fake_urlopen(url, timeout):
            captured.append(url)
            return Response()

        with mock.patch.object(FREEZER.urllib.request, "urlopen", side_effect=fake_urlopen):
            self.assertEqual(FREEZER._registry_token(repository), "stub-token")

        self.assertEqual(len(captured), 1)
        parsed = urlsplit(captured[0])
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, "auth.docker.io")
        self.assertEqual(
            parse_qs(parsed.query),
            {
                "service": ["registry.docker.io"],
                "scope": [f"repository:{repository}:pull"],
            },
        )


if __name__ == "__main__":
    unittest.main()
