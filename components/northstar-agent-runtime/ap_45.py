"""pascal_row utility."""

def pascal_row(n):
    row = [1]
    for k in range(1, n+1):
        row.append(row[-1]*(n-k+1)//k)
    return row


def _self_test():
    assert pascal_row(4) == [1,4,6,4,1]
    assert pascal_row(0) == [1]


if __name__ == "__main__":
    _self_test()
    print("ap_45: OK")
