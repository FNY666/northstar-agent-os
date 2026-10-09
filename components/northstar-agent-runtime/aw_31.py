"""True if brackets are balanced."""
def bracket_ok(s):
    pairs = {")": "(", "]": "[", "}": "{"}
    st = []
    for ch in s:
        if ch in "([{":
            st.append(ch)
        elif ch in pairs:
            if not st or st.pop() != pairs[ch]:
                return False
    return not st
if __name__ == "__main__":
    assert bracket_ok("()[]{}") is True
    assert bracket_ok("([)]") is False
    assert bracket_ok("") is True
    print("ok")
