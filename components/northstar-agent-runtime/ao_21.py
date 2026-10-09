"""ao_21: camel_to_snake utility (stdlib only)."""

import re
def camel_to_snake(s):
    return re.sub(r'(?<!^)(?=[A-Z])', '_', s).lower()


def _self_test():
    assert camel_to_snake('helloWorld') == 'hello_world', "camel_to_snake('helloWorld') == 'hello_world'"
    assert camel_to_snake('x') == 'x', "camel_to_snake('x') == 'x'"


if __name__ == "__main__":
    _self_test()
    print("ok")
