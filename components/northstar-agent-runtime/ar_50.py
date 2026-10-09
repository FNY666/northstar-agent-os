"""Tiny utility: ar_50 (sliding windows)."""

def windows(xs,n):
    return [xs[i:i+n] for i in range(len(xs)-n+1)]

def self_test():
    assert windows([1,2,3,4],2)==[[1,2],[2,3],[3,4]]
    assert windows([1],2)==[]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
