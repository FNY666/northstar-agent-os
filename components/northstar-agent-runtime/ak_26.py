"""ak_26: Zip-with index."""

def enumerate1(xs):
    return list(enumerate(xs, start=1))

if __name__ == '__main__':
    assert enumerate1(['a', 'b']) == [(1, 'a'), (2, 'b')]
    assert enumerate1([]) == []
    print('ok')
