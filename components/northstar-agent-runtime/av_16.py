"""Slugify: lowercase, non-alnum runs become hyphens."""
import re
def slugify(text):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s
if __name__ == "__main__":
    assert slugify("Hello, World!") == "hello-world"
    assert slugify("  A  B  ") == "a-b"
    assert slugify("abc") == "abc"
    print("ok")
