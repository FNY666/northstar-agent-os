"""Run-length encode a string as (char, count) pairs."""
def run_length(s):
    out, i = [], 0
    while i < len(s):
        j = i
        while j < len(s) and s[j] == s[i]:
            j += 1
        out.append((s[i], j - i)); i = j
    return out
if __name__ == "__main__":
    assert run_length("aaabb") == [("a",3),("b",2)]
    assert run_length("") == []
    assert run_length("a") == [("a",1)]
    print("ok")
