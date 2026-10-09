"""Levenshtein distance. stdlib only."""

def levenshtein_simple(a, b):
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j]+1, cur[-1]+1, prev[j-1]+(ca != cb)))
        prev = cur
    return prev[-1]

def test():
    assert levenshtein_simple('kitten', 'sitting') == 3
    assert levenshtein_simple('', '') == 0
    assert levenshtein_simple('abc', 'abc') == 0

if __name__ == '__main__':
    test(); print('ok')
