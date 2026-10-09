"""Transpose a rectangular matrix (list of rows)."""
def transpose(matrix):
    return [list(row) for row in zip(*matrix)]
if __name__ == "__main__":
    assert transpose([[1, 2], [3, 4]]) == [[1, 3], [2, 4]]
    assert transpose([[1, 2, 3]]) == [[1], [2], [3]]
    assert transpose([]) == []
    print("ok")
