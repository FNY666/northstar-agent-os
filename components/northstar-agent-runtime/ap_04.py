"""dedup utility."""

def dedup(lst):
    seen, out = set(), []
    for x in lst:
        if x not in seen:
            seen.add(x); out.append(x)
    return out


def _self_test():
    assert dedup([1,2,2,3,1]) == [1,2,3]
    assert dedup([]) == []


if __name__ == "__main__":
    _self_test()
    print("ap_04: OK")
