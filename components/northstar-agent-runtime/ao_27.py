"""ao_27: to_roman utility (stdlib only)."""

def to_roman(n):
    vals = [(1000,'M'),(900,'CM'),(500,'D'),(400,'CD'),(100,'C'),(90,'XC'),(50,'L'),(40,'XL'),(10,'X'),(9,'IX'),(5,'V'),(4,'IV'),(1,'I')]
    out = ''
    for v, r in vals:
        while n >= v: out += r; n -= v
    return out


def _self_test():
    assert to_roman(1994) == 'MCMXCIV', "to_roman(1994) == 'MCMXCIV'"
    assert to_roman(1) == 'I', "to_roman(1) == 'I'"


if __name__ == "__main__":
    _self_test()
    print("ok")
