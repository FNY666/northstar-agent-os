"""ao_24: base64dec utility (stdlib only)."""

import base64
def base64dec(s):
    return base64.b64decode(s.encode()).decode()


def _self_test():
    assert base64dec('aGk=') == 'hi', "base64dec('aGk=') == 'hi'"
    assert base64dec('') == '', "base64dec('') == ''"


if __name__ == "__main__":
    _self_test()
    print("ok")
