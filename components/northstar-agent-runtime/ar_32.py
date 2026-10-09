"""Tiny utility: ar_32 (merge sorted)."""

def merge(a,b):
    i=j=0;out=[]
    while i<len(a) and j<len(b):
        if a[i]<=b[j]:out.append(a[i]);i+=1
        else:out.append(b[j]);j+=1
    return out+a[i:]+b[j:]

def self_test():
    assert merge([1,3],[2,4])==[1,2,3,4]
    assert merge([],[1])==[1]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
