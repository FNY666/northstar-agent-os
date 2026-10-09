"""ao_29: levenshtein utility (stdlib only)."""

def levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j-1] + 1, prev[j-1] + (ca != cb))
        prev = cur
    return prev[-1]


def _self_test():
    assert levenshtein('kitten', 'sitting') == 3, "levenshtein('kitten', 'sitting') == 3"
    assert levenshtein('abc', 'abc') == 0, "levenshtein('abc', 'abc') == 0"


if __name__ == "__main__":
    _self_test()
    print("ok")
