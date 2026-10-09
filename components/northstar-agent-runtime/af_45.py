"""AF-module: find_emails -- Find email addresses in text with a regex."""
from __future__ import annotations
VERSION = "af_45"
import re
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
def find_emails(s: str) -> list:
    return EMAIL_RE.findall(s)

def main() -> None:
    assert find_emails('a@b.com and x@y.io') == ['a@b.com', 'x@y.io']
    assert find_emails('no mail here') == []
    assert find_emails('Contact me@home') == []
    print("af_45 find_emails OK")
if __name__ == "__main__": main()
