"""ax_26: to_snake utility (stdlib only)."""
def to_snake(s):
    import re
    return re.sub(r'(?<!^)(?=[A-Z])', '_', s).lower()


def run_tests():
    assert (to_snake('CamelCase')) == 'camel_case', "to_snake('CamelCase')"
    assert (to_snake('abc')) == 'abc', "to_snake('abc')"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_26: ok")
