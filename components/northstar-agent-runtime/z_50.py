"""z_50: weighted_choice."""
from __future__ import annotations
VERSION = "z_50.v1"
def weighted_choice(items,weights,seed=0):
    import random
    rng=random.Random(seed)
    return rng.choices(items,weights=weights,k=1)[0]

def main() -> None:
    assert weighted_choice(['a','b'],[1,1],seed=1) in ('a','b')
    assert weighted_choice(['a'],[5])=='a'
    print('z_50 weighted_choice OK')

if __name__ == "__main__": main()
