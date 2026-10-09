"""Insertion position of x in a sorted list (bisect left)."""
import bisect
def insert_pos(sorted_list, x):
    return bisect.bisect_left(sorted_list, x)
if __name__ == "__main__":
    assert insert_pos([1, 3, 5], 4) == 2
    assert insert_pos([1, 3, 5], 1) == 0
    assert insert_pos([], 9) == 0
    print("ok")
