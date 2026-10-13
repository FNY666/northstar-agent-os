# Task fixture

`extract(archive, destination)` reads ZIP files, returns member names, and writes safe nested files. Validate every member before extraction. Reject absolute paths, Windows drive paths, parent traversal, archive links, and existing symlink escapes.

Run public checks with `python3 -m unittest discover -s tests -v`.
