"""R26a: provider-supplied text must never carry a credential into a report.

The R20/R23 redaction only covered ``ValueError`` messages. A provider HTTP
error body is provider-supplied text that reaches ``error_detail`` through
``PlannerModelCallFailed``, so that path needs the same guarantee.
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [
    str(ROOT),
    str(ROOT.parent / "northstar-host"),
    str(ROOT.parent / "northstar-agent-interop"),
    str(ROOT.parent / "northstar-run-contract"),
]

from agent_driver import AgentDriver  # noqa: E402
from agent_entry import ExpectedArtifact  # noqa: E402
from openai_compatible_planner import (  # noqa: E402
    OpenAICompatiblePlannerCaller,
    OpenAICompatiblePlannerConfig,
)
from planner_adapter import PlannerModelCallFailed, TypedPlannerAdapter  # noqa: E402

# Fake values. OPAQUE has no recognisable credential prefix on purpose.
OPAQUE = "Zq8vN3xT7mKp2LwR9aYc4HdE6bFs1JgU"
SHAPED = "sk-or-v1-0123456789abcdef0123456789abcdef"
# Same length as a real provider key (67): shorter keys hide fragment leaks
# behind the 8-character detection window.
LONGKEY = OPAQUE + "Wn5Pd8QrY2Vh7Bm3Cx6Lk9Ts4Jf1Ge0Ua8Z"


def _leaks_fragment(text, key, window=8):
    """True if any ``window``-long slice of ``key`` appears in ``text``."""
    text = text or ""
    return any(key[i:i + window] in text for i in range(len(key) - window + 1))


def _leaks_fragment(text, key, window=8):
    """True if any ``window``-long slice of ``key`` appears in ``text``."""
    text = text or ""
    return any(key[i:i + window] in text for i in range(len(key) - window + 1))


def _config(env_name):
    return OpenAICompatiblePlannerConfig(
        endpoint="https://planner.example/v1/chat/completions",
        api_key_env=env_name, model_id="m", provider="p", model_revision="r",
    )


def _http_error_transport(message):
    def transport(request, timeout):
        raise HTTPError(
            request.full_url, 401, "Unauthorized", {},
            io.BytesIO(json.dumps({"error": {"message": message}}).encode()),
        )
    return transport


class ProviderTextRedactionTests(unittest.TestCase):
    def test_direct_construction_redacts_the_active_key(self):
        with mock.patch.dict(os.environ, {"KAKOUAI_API_KEY": OPAQUE}, clear=True):
            error = PlannerModelCallFailed("bad key " + OPAQUE)
        self.assertNotIn(OPAQUE, error.detail)
        self.assertNotIn(OPAQUE, str(error))
        self.assertIn("<redacted>", error.detail)

    def test_direct_construction_redacts_key_shaped_text_without_env(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            error = PlannerModelCallFailed("bad key " + SHAPED)
        self.assertNotIn(SHAPED, error.detail)

    def test_http_error_body_echoing_the_key_is_redacted(self):
        for env_name in ("KAKOUAI_API_KEY", "OPENROUTER_API_KEY", "MY_PROVIDER_KEY"):
            for key in (OPAQUE, SHAPED):
                with self.subTest(env=env_name, key=key[:6]):
                    caller = OpenAICompatiblePlannerCaller(
                        _config(env_name),
                        transport=_http_error_transport("Incorrect API key provided: " + key),
                    )
                    with mock.patch.dict(os.environ, {env_name: key}, clear=True):
                        with self.assertRaises(PlannerModelCallFailed) as raised:
                            caller(goal="x", context={}, repair_error=None, attempt=1)
                    self.assertNotIn(key, raised.exception.detail)
                    self.assertIn("HTTP 401", raised.exception.detail)

    def test_key_straddling_the_truncation_boundary_leaves_no_fragment(self):
        # Provider text used to be cut to 400 characters *before* the credential
        # was replaced, and the constructor then cut the whole message again.
        # A key crossing the first cut survived as a fragment no exact match
        # could catch. The fixture must put the key across THAT cut, measured
        # on the provider text itself (not on the final message).
        self.assertEqual(len(LONGKEY), 67)
        for pad in (340, 355, 365):
            with self.subTest(provider_text_pad=pad):
                self.assertLess(pad, 400)
                self.assertGreater(pad + len(LONGKEY), 400)
                caller = OpenAICompatiblePlannerCaller(
                    _config("OPENROUTER_API_KEY"),
                    transport=_http_error_transport("x" * pad + LONGKEY),
                )
                with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": LONGKEY}, clear=True):
                    with self.assertRaises(PlannerModelCallFailed) as raised:
                        caller(goal="x", context={}, repair_error=None, attempt=1)
                self.assertFalse(
                    _leaks_fragment(raised.exception.detail, LONGKEY),
                    "an 8+ character fragment of the key survived truncation",
                )

    def test_ordinary_provider_diagnostics_survive_redaction(self):
        caller = OpenAICompatiblePlannerCaller(
            _config("TEST_PLANNER_API_KEY"),
            transport=_http_error_transport("need fewer max_tokens"),
        )
        with mock.patch.dict(os.environ, {"TEST_PLANNER_API_KEY": OPAQUE}, clear=True):
            with self.assertRaises(PlannerModelCallFailed) as raised:
                caller(goal="x", context={}, repair_error=None, attempt=1)
        self.assertIn("need fewer max_tokens", raised.exception.detail)

    def test_redaction_does_not_damage_ordinary_provider_text(self):
        # Negative control: over-redaction would hide the very diagnostics this
        # channel exists to preserve (URLs, non-ASCII messages, short tokens).
        texts = (
            "model deepseek-v4.1-flash is overloaded, retry in 20s",
            "当前分组没有可用套餐，请检查套餐配置或开通套餐后重试。",
            "see https://docs.example.com/errors/rate-limit#rpm for details",
            "request id req_8f3a2c1d9e7b4a60 failed: skill-level 7 not allowed",
        )
        for text in texts:
            with self.subTest(text=text[:24]):
                caller = OpenAICompatiblePlannerCaller(
                    _config("OPENROUTER_API_KEY"), transport=_http_error_transport(text),
                )
                with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": LONGKEY}, clear=True):
                    with self.assertRaises(PlannerModelCallFailed) as raised:
                        caller(goal="x", context={}, repair_error=None, attempt=1)
                self.assertIn(text, raised.exception.detail)
                self.assertNotIn("<redacted>", raised.exception.detail)

    def test_key_does_not_reach_the_run_report_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            (workspace / "README.md").write_text("x\n", encoding="utf-8")
            caller = OpenAICompatiblePlannerCaller(
                _config("OPENROUTER_API_KEY"),
                transport=_http_error_transport("Incorrect API key provided: " + OPAQUE),
            )
            driver = AgentDriver(
                workspace_root=workspace, evidence_dir=root / "evidence",
                expectations=[ExpectedArtifact("out/x.md", contains=("x",))],
                clock=lambda: 100,
            )
            with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": OPAQUE}, clear=True):
                outcome = driver.run("leak-check", "write x", TypedPlannerAdapter(caller))
            report = json.dumps(outcome.as_dict(), ensure_ascii=False, default=str)
        self.assertNotIn(OPAQUE, report)
        self.assertIn("HTTP 401", report)


if __name__ == "__main__":
    unittest.main()
