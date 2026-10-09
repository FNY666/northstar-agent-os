"""Tiny utility: ar_01 (array rotate left)."""

def rotl(xs,k):
    k%=len(xs);return xs[k:]+xs[:k]

def self_test():
    assert rotl([1,2,3,4],1)==[2,3,4,1]
    assert rotl([1,2,3],0)==[1,2,3]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
