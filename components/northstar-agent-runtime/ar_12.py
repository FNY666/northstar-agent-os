"""Tiny utility: ar_12 (dedupe preserving order)."""

def dedupe(xs):
    seen=[]
    for x in xs:
        if x not in seen:seen.append(x)
    return seen

def self_test():
    assert dedupe([1,2,1,3,2])==[1,2,3]
    assert dedupe([])==[]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
