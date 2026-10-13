"""Collect pages from fetch(cursor) returning items and next_cursor."""
def collect(fetch):
    cursor = None
    items = []
    for _ in range(100):
        page = fetch(cursor)
        items.extend(page["items"][:-1])
        cursor = page["next_cursor"]
        if cursor is None:
            return items
    raise RuntimeError("too many pages")
