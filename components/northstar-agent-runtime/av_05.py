"""Deduplicate preserving first-occurrence order."""
def dedup(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out
if __name__ == "__main__":
    assert dedup([1, 2, 1, 3, 2]) == [1, 2, 3]
    assert dedup("abac") == ["a", "b", "c"]
    assert dedup([]) == []
    print("ok")
