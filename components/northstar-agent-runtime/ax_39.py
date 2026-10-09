"""ax_39: uuid4_str utility (stdlib only)."""
def uuid4_str():
    import uuid
    return str(uuid.uuid4())


def run_tests():
    assert (len(uuid4_str())) == 36, 'len(uuid4_str())'
    assert (uuid4_str().count('-')) == 4, "uuid4_str().count('-')"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_39: ok")
