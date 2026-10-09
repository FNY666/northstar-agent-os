"""ax_27: to_camel utility (stdlib only)."""
def to_camel(s):
    parts = s.split('_')
    return parts[0] + ''.join(p.capitalize() for p in parts[1:])


def run_tests():
    assert (to_camel('snake_case')) == 'snakeCase', "to_camel('snake_case')"
    assert (to_camel('a')) == 'a', "to_camel('a')"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_27: ok")
