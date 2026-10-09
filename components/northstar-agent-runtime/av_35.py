"""Multiply two matrices."""
def matmul(a, b):
    bt = list(zip(*b))
    return [[sum(x * y for x, y in zip(row, col)) for col in bt] for row in a]
if __name__ == "__main__":
    assert matmul([[1, 2], [3, 4]], [[5, 6], [7, 8]]) == [[19, 22], [43, 50]]
    assert matmul([[2]], [[3]]) == [[6]]
    assert matmul([[1, 0], [0, 1]], [[9, 8], [7, 6]]) == [[9, 8], [7, 6]]
    print("ok")
