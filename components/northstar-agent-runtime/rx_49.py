"""Docker image name matcher

What this IS: a matcher for name[:tag] image references.

What this IS NOT: a registry client.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_49_VERSION = "rx-49.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-49.v1"

DOCKER_IMG_RE = re.compile(r'[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?')
def is_docker_image(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return DOCKER_IMG_RE.fullmatch(text) is not None


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    assert is_docker_image("nginx")
    assert is_docker_image("my-app:1.2.3")
    assert is_docker_image("a.b-c_d")
    assert not is_docker_image("UPPER")
    assert not is_docker_image("-bad")
    assert stdlib_only()
    print("49-docker_img OK")


if __name__ == "__main__":
    main()
