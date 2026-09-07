"""Release readiness: one version for every packaged component.

The five pip-installable components are released together from a single tag,
so their ``pyproject.toml`` versions must stay identical and parse as a
release version (``major.minor.patch``, no dev/local suffix). The runtime's
``_version.py`` must match as well — it is the single source the CLI prints
and the MCP handshake advertises.
"""
import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGED = (
    "northstar-run-contract",
    "northstar-host",
    "northstar-durable-run",
    "northstar-agent-interop",
    "northstar-agent-runtime",
)
RELEASE_RE = re.compile(r"^\d+\.\d+\.\d+$")


def component_version(name: str) -> str:
    pyproject = tomllib.loads((ROOT / "components" / name / "pyproject.toml").read_text(encoding="utf-8"))
    return pyproject["project"]["version"]


def runtime_module_version() -> str:
    text = (ROOT / "components" / "northstar-agent-runtime" / "_version.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if not match:
        raise AssertionError("could not parse __version__ from _version.py")
    return match.group(1)


class ReleaseVersionTests(unittest.TestCase):
    def test_every_component_version_is_a_release_version(self):
        for name in PACKAGED:
            with self.subTest(component=name):
                version = component_version(name)
                self.assertRegex(version, RELEASE_RE, f"{name} must carry a plain release version")

    def test_all_packaged_components_share_one_version(self):
        versions = {name: component_version(name) for name in PACKAGED}
        self.assertEqual(
            len(set(versions.values())),
            1,
            f"components drifted apart; a release is one version for all: {versions}",
        )

    def test_runtime_version_module_matches_the_release_version(self):
        self.assertEqual(runtime_module_version(), component_version("northstar-agent-runtime"))


if __name__ == "__main__":
    unittest.main()
