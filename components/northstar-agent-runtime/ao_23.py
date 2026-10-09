"""ao_23: base64enc utility (stdlib only)."""

import base64
def base64enc(s):
    return base64.b64encode(s.encode()).decode()


def _self_test():
    assert base64enc('hi') == 'aGk=', "base64enc('hi') == 'aGk='"
    assert base64enc('') == '', "base64enc('') == ''"


if __name__ == "__main__":
    _self_test()
    print("ok")
