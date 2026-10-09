"""Deduplicate preserving first-seen order."""
def dedup_keep(xs):
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x); out.append(x)
    return out
if __name__ == "__main__":
    assert dedup_keep([3,1,3,2,1]) == [3,1,2]
    assert dedup_keep([]) == []
    assert dedup_keep("abac") == list("abc")
    print("ok")
