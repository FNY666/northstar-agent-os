"""AF-module: ensure_parent -- Create a path's parent dirs; return the Path."""
from __future__ import annotations
VERSION = "af_48"
from pathlib import Path
def ensure_parent(p) -> Path:
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

def main() -> None:
    import tempfile, os
    d = tempfile.mkdtemp()
    q = ensure_parent(os.path.join(d, 'sub', 'f.txt'))
    assert q.parent.is_dir()
    assert str(q).endswith('f.txt')
    assert ensure_parent(q) == q
    print("af_48 ensure_parent OK")
if __name__ == "__main__": main()
