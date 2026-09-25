import argparse
import unittest

import support  # noqa: F401
from agents import AgentDefinition
from run_setup import resolve_ceilings


class AgentCeilingTests(unittest.TestCase):
    def _args(self):
        return argparse.Namespace(
            max_turns=3,
            max_tool_calls=4,
            max_budget_usd=None,
            compaction_threshold_tokens=60_000,
            halt_on_denial=False,
        )

    def test_agent_definition_cannot_raise_max_turns(self):
        definition = AgentDefinition(name="wide", max_turns=12, max_tool_calls=4)
        ceilings = resolve_ceilings(self._args(), definition, None, None)
        self.assertLessEqual(ceilings.max_turns, self._args().max_turns)

    def test_agent_definition_cannot_raise_max_tool_calls(self):
        definition = AgentDefinition(name="wide", max_turns=3, max_tool_calls=20)
        ceilings = resolve_ceilings(self._args(), definition, None, None)
        self.assertLessEqual(ceilings.max_tool_calls, self._args().max_tool_calls)


if __name__ == "__main__":
    unittest.main()
