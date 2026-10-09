"""ax_36: b64_decode utility (stdlib only)."""
def b64_decode(s):
    import base64
    return base64.b64decode(s).decode()


def run_tests():
    assert (b64_decode('aGk=')) == 'hi', "b64_decode('aGk=')"
    assert (b64_decode('')) == '', "b64_decode('')"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_36: ok")
