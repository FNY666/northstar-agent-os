"""ak_42: Count set bits."""

def popcount(n):
    return bin(n).count('1')

if __name__ == '__main__':
    assert popcount(13) == 3
    assert popcount(0) == 0
    print('ok')
