"""Static toy fixture only; this function is intentionally never invoked."""

import yaml


def parse_fixture_document(document: str):
    return yaml.safe_load(document)
