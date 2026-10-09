"""ax_34: hex_encode utility (stdlib only)."""
def hex_encode(b):
    return b.hex() if isinstance(b, bytes) else bytes(b, 'utf-8').hex()


def run_tests():
    assert (hex_encode(b'ab')) == '6162', "hex_encode(b'ab')"
    assert (hex_encode('ab')) == '6162', "hex_encode('ab')"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_34: ok")
