"""ak_50: Wrap text to width."""

def wrap(s, w):
    import textwrap as tw
    return tw.wrap(s, w)

if __name__ == '__main__':
    assert wrap('aaa bbb ccc', 5) == ['aaa', 'bbb', 'ccc']
    assert wrap('', 5) == []
    print('ok')
