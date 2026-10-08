"""URL helpers: parse, validate, join, query. What this IS: URL plumbing without requests. What this IS NOT: not a fetcher."""

from __future__ import annotations

import ast
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

#: Module version.
UTIL_11_VERSION = "util-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-11.v1"


class UrlError(Exception):
    """URL helper failure."""


def parse_url(url: str) -> dict:
    p = urlparse(url or "")
    return {
        "scheme": p.scheme,
        "host": p.hostname or "",
        "port": p.port,
        "path": p.path,
        "query": dict(parse_qsl(p.query)),
    }


def is_http_url(url: str) -> bool:
    try:
        p = urlparse(url or "")
    except ValueError:
        return False
    return p.scheme in ("http", "https") and bool(p.hostname)


def join_url(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def get_domain(url: str) -> str:
    return urlparse(url or "").hostname or ""


def with_query(url: str, params: dict) -> str:
    p = urlparse(url or "")
    q = dict(parse_qsl(p.query))
    q.update({k: str(v) for k, v in params.items()})
    return urlunparse(p._replace(query=urlencode(q)))


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib', 'urllib']
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
    info = parse_url("https://example.com:8080/a?x=1")
    assert info["host"] == "example.com" and info["port"] == 8080
    assert info["query"] == {"x": "1"}
    assert is_http_url("https://x.com") is True
    assert is_http_url("ftp://x.com") is False
    assert join_url("https://x.com/a", "b") == "https://x.com/a/b"
    assert "y=2" in with_query("https://x.com/?y=1", {"y": 2, "z": 3})
    print("url helpers OK")


if __name__ == "__main__":
    main()
