"""to_snake utility."""

def to_snake(s):
    import re
    return re.sub(r'(?<!^)(?=[A-Z])', '_', s).lower()


def _self_test():
    assert to_snake('camelCase') == 'camel_case'
    assert to_snake('a') == 'a'


if __name__ == "__main__":
    _self_test()
    print("ap_37: OK")
