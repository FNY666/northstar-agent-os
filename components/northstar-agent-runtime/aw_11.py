"""Most common element (first wins ties)."""
def mode_of(xs):
    return max(sorted(set(xs)), key=xs.count)
if __name__ == "__main__":
    assert mode_of([1,2,2,3]) == 2
    assert mode_of([5]) == 5
    assert mode_of("abca") == "a"
    print("ok")
