"""ax_15: top_n utility (stdlib only)."""
def top_n(items, n):
    return sorted(items, reverse=True)[:n]


def run_tests():
    assert (top_n([3,1,2], 2)) == [3, 2], 'top_n([3,1,2], 2)'
    assert (top_n([], 5)) == [], 'top_n([], 5)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_15: ok")
