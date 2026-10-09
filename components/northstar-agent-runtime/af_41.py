"""AF-module: url_add_query -- Append query params to a URL, preserving existing ones."""
from __future__ import annotations
VERSION = "af_41"
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl
def url_add_query(url: str, **params) -> str:
    p = urlparse(url)
    q = parse_qsl(p.query)
    q.extend(params.items())
    return urlunparse(p._replace(query=urlencode(q)))

def main() -> None:
    assert url_add_query('http://x/y', a='1') == 'http://x/y?a=1'
    assert url_add_query('http://x/y?a=1', b='2') == 'http://x/y?a=1&b=2'
    assert 'q=hello+world' in url_add_query('http://x/', q='hello world')
    print("af_41 url_add_query OK")
if __name__ == "__main__": main()
