"""AF-module: html_escape -- Escape HTML special chars; optional quote escaping."""
from __future__ import annotations
VERSION = "af_42"
import html
def html_escape(s: str, quote: bool = True) -> str:
    return html.escape(s, quote=quote)

def main() -> None:
    assert html_escape('<b>"x"</b>') == '&lt;b&gt;&quot;x&quot;&lt;/b&gt;'
    assert html_escape('a&b') == 'a&amp;b'
    assert html_escape('plain') == 'plain'
    print("af_42 html_escape OK")
if __name__ == "__main__": main()
