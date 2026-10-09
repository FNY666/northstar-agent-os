"""Capitalize first letter of each word."""
def title_case(s):
    return " ".join(w[:1].upper() + w[1:].lower() for w in s.split(" "))
if __name__ == "__main__":
    assert title_case("hello world") == "Hello World"
    assert title_case("aBC") == "Abc"
    assert title_case("") == ""
    print("ok")
