"""ak_48: Join lines with numbered prefix."""

def numbered(lines):
    return [f'{i}. {l}' for i, l in enumerate(lines, 1)]

if __name__ == '__main__':
    assert numbered(['a', 'b']) == ['1. a', '2. b']
    assert numbered([]) == []
    print('ok')
