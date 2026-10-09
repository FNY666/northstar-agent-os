"""ao_20: snake_to_camel utility (stdlib only)."""

def snake_to_camel(s):
    parts = s.split('_')
    return parts[0] + ''.join(p.capitalize() for p in parts[1:])


def _self_test():
    assert snake_to_camel('hello_world') == 'helloWorld', "snake_to_camel('hello_world') == 'helloWorld'"
    assert snake_to_camel('x') == 'x', "snake_to_camel('x') == 'x'"


if __name__ == "__main__":
    _self_test()
    print("ok")
