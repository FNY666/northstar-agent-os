"""Split a sequence into chunks of size n."""
def chunks(seq, n):
    return [seq[i:i + n] for i in range(0, len(seq), n)]
if __name__ == "__main__":
    assert chunks([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]
    assert chunks([], 3) == []
    assert chunks("abcd", 3) == ["abc", "d"]
    print("ok")
