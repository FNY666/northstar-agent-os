"""Static toy fixture only; these functions are intentionally never invoked."""


def evaluate_fixture(expression: str):
    return eval(expression)


def execute_fixture(source: str):
    exec(source, {})
