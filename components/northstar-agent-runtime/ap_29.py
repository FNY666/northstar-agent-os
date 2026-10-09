"""find_max_index utility."""

def find_max_index(lst):
    return max(range(len(lst)), key=lambda i: lst[i]) if lst else -1


def _self_test():
    assert find_max_index([1,5,3]) == 1
    assert find_max_index([]) == -1


if __name__ == "__main__":
    _self_test()
    print("ap_29: OK")
