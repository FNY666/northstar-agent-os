"""Static toy fixture only; this function is intentionally never invoked."""

import requests


def fetch_fixture_endpoint():
    return requests.get("fixture-endpoint", verify=False, timeout=1)
