"""to_camel utility."""

def to_camel(s):
    parts = s.split('_')
    return parts[0] + ''.join(p[:1].upper()+p[1:] for p in parts[1:])


def _self_test():
    assert to_camel('snake_case') == 'snakeCase'
    assert to_camel('a') == 'a'


if __name__ == "__main__":
    _self_test()
    print("ap_38: OK")
