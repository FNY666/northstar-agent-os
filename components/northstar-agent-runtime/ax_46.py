"""ax_46: sliding_window utility (stdlib only)."""
def sliding_window(items, n):
    return [items[i:i+n] for i in range(len(items)-n+1)]


def run_tests():
    assert (sliding_window([1,2,3,4], 2)) == [[1, 2], [2, 3], [3, 4]], 'sliding_window([1,2,3,4], 2)'
    assert (sliding_window([1], 2)) == [], 'sliding_window([1], 2)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_46: ok")
