"""Tiny utility: ar_25 (run length encode)."""

def rle(s):
    out=[];i=0
    while i<len(s):
        j=i
        while j<len(s) and s[j]==s[i]:j+=1
        out.append((s[i],j-i));i=j
    return out

def self_test():
    assert rle('aaabbc')==[('a',3),('b',2),('c',1)]
    assert rle('')==[]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
