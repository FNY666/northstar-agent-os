"""Tiny utility: ar_31 (insertion sort)."""

def isort(xs):
    xs=list(xs)
    for i in range(1,len(xs)):
        k=xs[i];j=i-1
        while j>=0 and xs[j]>k:
            xs[j+1]=xs[j];j-=1
        xs[j+1]=k
    return xs

def self_test():
    assert isort([3,1,2])==[1,2,3]
    assert isort([])==[]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
