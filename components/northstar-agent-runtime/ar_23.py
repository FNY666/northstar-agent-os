"""Tiny utility: ar_23 (camel to snake)."""

def camel_to_snake(s):
    import re
    return re.sub(r'(?<!^)(?=[A-Z])','_',s).lower()

def self_test():
    assert camel_to_snake('camelCase')=='camel_case'
    assert camel_to_snake('ABC')=='a_b_c'
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
