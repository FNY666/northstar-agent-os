"""Tiny utility: aq_48."""

snake_case = lambda s: s.lower().replace(' ', '_')

def self_test():
    assert snake_case('Hello World') == 'hello_world'
    assert snake_case('a') == 'a'
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
