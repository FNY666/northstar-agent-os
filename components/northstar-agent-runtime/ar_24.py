"""Tiny utility: ar_24 (snake to camel)."""

def snake_to_camel(s):
    parts=s.split('_')
    return parts[0]+''.join(p.capitalize() for p in parts[1:])

def self_test():
    assert snake_to_camel('snake_case')=='snakeCase'
    assert snake_to_camel('a')=='a'
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
