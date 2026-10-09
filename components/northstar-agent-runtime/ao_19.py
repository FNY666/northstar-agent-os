"""ao_19: title_case utility (stdlib only)."""

def title_case(s):
    return ' '.join(w[:1].upper() + w[1:].lower() for w in s.split())


def _self_test():
    assert title_case('hello world') == 'Hello World', "title_case('hello world') == 'Hello World'"
    assert title_case('') == '', "title_case('') == ''"


if __name__ == "__main__":
    _self_test()
    print("ok")
