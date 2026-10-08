"""SSRF detection in output (D-OUT-027), Simulated."""
from __future__ import annotations
import ast, re
from ipaddress import ip_address
VERSION = "ssrf-detect.v1"
def is_private_url(url: str) -> bool:
    try:
        host = re.search(r"https?://([^/:]+)", url)
        if not host: return False
        h = host.group(1)
        if h in ("localhost", "127.0.0.1", "::1"): return True
        try:
            ip = ip_address(h)
            return ip.is_private or ip.is_loopback
        except: return False
    except: return False
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "ipaddress", "pathlib", "re", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert is_private_url("http://127.0.0.1/")
    assert is_private_url("http://192.168.1.1/")
    assert not is_private_url("https://example.com/")
    assert stdlib_only()
    print("ssrf-detect OK")
if __name__ == "__main__": main()
