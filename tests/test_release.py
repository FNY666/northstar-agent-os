"""Release readiness: one version for every packaged component.

The five pip-installable components are released together from a single tag,
so their ``pyproject.toml`` versions must stay identical. Between releases the
version carries a ``.devN`` suffix (unreleased development state); a *release*
version is plain ``major.minor.patch`` with no suffix — the release workflow
refuses to publish a dev-suffixed version, so a tag can only be cut when the
readiness gate has been passed. The runtime's ``_version.py`` must match as
well — it is the single source the CLI prints and the MCP handshake
advertises.
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
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(\.dev\d+)?$")


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
    def test_every_component_version_is_a_version(self):
        for name in PACKAGED:
            with self.subTest(component=name):
                version = component_version(name)
                self.assertRegex(version, VERSION_RE, f"{name} has a malformed version {version!r}")

    def test_all_packaged_components_share_one_version(self):
        versions = {name: component_version(name) for name in PACKAGED}
        self.assertEqual(
            len(set(versions.values())),
            1,
            f"components drifted apart; a release is one version for all: {versions}",
        )

    def test_runtime_version_module_matches_the_release_version(self):
        self.assertEqual(runtime_module_version(), component_version("northstar-agent-runtime"))

    def test_dev_suffix_marks_unreleased_state_and_is_opt_in_for_release(self):
        # Between releases the aligned version must be dev-suffixed so nobody
        # mistakes the working tree for a shipped release; dropping the suffix
        # is the explicit "ready to release" step (enforced by release.yml).
        self.assertIn(".dev", component_version("northstar-agent-runtime"))


if __name__ == "__main__":
    unittest.main()
