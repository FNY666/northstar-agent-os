"""au_15: snake_case to camelCase."""
def snake_to_camel(s):
    """Convert snake_case to camelCase."""
    parts = s.split('_')
    return parts[0] + ''.join(p[:1].upper()+p[1:] for p in parts[1:])

def _run_tests():
    assert snake_to_camel('snake_case') == 'snakeCase'
    assert snake_to_camel('a') == 'a'

if __name__ == "__main__":
    _run_tests()
    print("au_15 OK")
