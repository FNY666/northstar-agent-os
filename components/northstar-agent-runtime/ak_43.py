"""ak_43: Trim each line of text."""

def trim_lines(s):
    return '\n'.join(line.strip() for line in s.splitlines())

if __name__ == '__main__':
    assert trim_lines('  a\n b ') == 'a\nb'
    assert trim_lines('') == ''
    print('ok')
