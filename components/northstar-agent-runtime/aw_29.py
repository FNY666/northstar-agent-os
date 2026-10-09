"""Caesar shift letters by k."""
def caesar(s, k):
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch)-97+k) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch)-65+k) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)
if __name__ == "__main__":
    assert caesar("abc", 1) == "bcd"
    assert caesar("xyz", 3) == "abc"
    assert caesar("A!", 26) == "A!"
    print("ok")
