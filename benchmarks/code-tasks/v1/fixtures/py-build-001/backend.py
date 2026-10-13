"""Dependency-free fixture backend; read package-data policy from pyproject.toml."""
import base64
import csv
import hashlib
import io
from pathlib import Path
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parent

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    settings = tomllib.loads((ROOT / "pyproject.toml").read_text())
    members = {"demo_templates/__init__.py": (ROOT / "demo_templates/__init__.py").read_bytes()}
    if settings["tool"]["demo"]["include-templates"]:
        for path in sorted((ROOT / "demo_templates/templates").rglob("*")):
            if path.is_file():
                members[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    info = "demo_templates-1.0.0.dist-info"
    members[info + "/METADATA"] = b"Metadata-Version: 2.1\nName: demo-templates\nVersion: 1.0.0\n\n"
    members[info + "/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: northstar-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    records = io.StringIO()
    writer = csv.writer(records, lineterminator="\n")
    for name, content in members.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        writer.writerow((name, "sha256=" + digest, len(content)))
    writer.writerow((info + "/RECORD", "", ""))
    members[info + "/RECORD"] = records.getvalue().encode()
    destination = Path(wheel_directory)
    destination.mkdir(parents=True, exist_ok=True)
    name = "demo_templates-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(destination / name, "w") as archive:
        for member, content in members.items():
            archive.writestr(member, content)
    return name
