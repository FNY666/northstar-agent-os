"""Extract a ZIP archive into destination and return its member names."""
from pathlib import Path
from zipfile import ZipFile

def extract(archive, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with ZipFile(archive) as source:
        source.extractall(destination)
        return source.namelist()
