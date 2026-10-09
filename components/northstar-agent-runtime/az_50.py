"""Cosine similarity. stdlib only."""

def cosine_sim(a, b):
    dotp = sum(x*y for x, y in zip(a, b))
    na = sum(x*x for x in a) ** 0.5
    nb = sum(x*x for x in b) ** 0.5
    return dotp / (na*nb) if na and nb else 0.0

def test():
    assert cosine_sim([1,0],[0,1]) == 0.0
    assert abs(cosine_sim([1,1],[1,1]) - 1.0) < 1e-9
    assert cosine_sim([],[]) == 0.0

if __name__ == '__main__':
    test(); print('ok')
