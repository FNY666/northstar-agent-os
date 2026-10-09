"""Collapse whitespace. stdlib only."""

import re

def strip_ws(s):
    return re.sub(r'\s+', ' ', s).strip()

def test():
    assert strip_ws('  a  b ') == 'a b'
    assert strip_ws('') == ''
    assert strip_ws('x') == 'x'

if __name__ == '__main__':
    test(); print('ok')
