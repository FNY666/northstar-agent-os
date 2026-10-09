"""Tiny utility: aq_49."""

camel_case = lambda s: (lambda w: w[0].lower() + ''.join(x.capitalize() for x in w[1:]))(s.split()) if s else ''

def self_test():
    assert camel_case('hello world') == 'helloWorld'
    assert camel_case('') == ''
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
