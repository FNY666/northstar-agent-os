"""Tiny utility: ar_02 (array rotate right)."""

def rotr(xs,k):
    k%=len(xs);return xs[-k:]+xs[:-k] if k else xs[:]

def self_test():
    assert rotr([1,2,3,4],1)==[4,1,2,3]
    assert rotr([1,2],2)==[1,2]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
