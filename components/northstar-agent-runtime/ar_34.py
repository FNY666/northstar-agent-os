"""Tiny utility: ar_34 (cumulative sum)."""

def cumsum(xs):
    out=[];t=0
    for x in xs:
        t+=x;out.append(t)
    return out

def self_test():
    assert cumsum([1,2,3])==[1,3,6]
    assert cumsum([])==[]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
