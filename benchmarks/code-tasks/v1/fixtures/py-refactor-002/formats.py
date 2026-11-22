"""Parse json or csv; unknown formats keep a stable error message."""
import csv
import io
import json

def parse(fmt, text):
    if fmt == "json":
        return json.loads(text)
    if fmt == "csv":
        return list(csv.reader(io.StringIO(text)))
    raise ValueError(f"unknown format: {fmt}")
