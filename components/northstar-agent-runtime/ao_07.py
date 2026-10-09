"""ao_07: reverse_str utility (stdlib only)."""

def reverse_str(s):
    return s[::-1]


def _self_test():
    assert reverse_str('abc') == 'cba', "reverse_str('abc') == 'cba'"
    assert reverse_str('') == '', "reverse_str('') == ''"


if __name__ == "__main__":
    _self_test()
    print("ok")
