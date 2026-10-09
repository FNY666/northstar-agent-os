"""unique_pairs utility."""

def unique_pairs(lst):
    return [(lst[i], lst[j]) for i in range(len(lst)) for j in range(i+1, len(lst))]


def _self_test():
    assert unique_pairs([1,2,3]) == [(1,2),(1,3),(2,3)]
    assert unique_pairs([1]) == []


if __name__ == "__main__":
    _self_test()
    print("ap_22: OK")
