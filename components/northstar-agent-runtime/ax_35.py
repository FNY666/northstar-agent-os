"""ax_35: b64_encode utility (stdlib only)."""
def b64_encode(s):
    import base64
    return base64.b64encode(s.encode()).decode()


def run_tests():
    assert (b64_encode('hi')) == 'aGk=', "b64_encode('hi')"
    assert (b64_encode('')) == '', "b64_encode('')"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_35: ok")
