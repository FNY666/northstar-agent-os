"""ax_02: chunk_list utility (stdlib only)."""
def chunk_list(items, size):
    return [items[i:i+size] for i in range(0, len(items), size)]


def run_tests():
    assert (chunk_list([1,2,3,4,5], 2)) == [[1, 2], [3, 4], [5]], 'chunk_list([1,2,3,4,5], 2)'
    assert (chunk_list([], 3)) == [], 'chunk_list([], 3)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_02: ok")
