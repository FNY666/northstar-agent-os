"""Static toy fixture only; these functions are intentionally never invoked."""


def parse_fixture_integer(text: str) -> int:
    return int(text)


def fixture_result() -> dict[str, int]:
    return {"result": 1}
