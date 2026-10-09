"""levenshtein utility."""

def levenshtein(a, b):
    r = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        nr, p = [i], i - 1
        for j, cb in enumerate(b, 1):
            nr.append(min(r[j] + 1, nr[-1] + 1, r[j - 1] + (ca != cb)))
        r = nr
    return r[-1]


def _selftest():
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("", "") == 0


if __name__ == "__main__":
    _selftest()
    print("ok")
