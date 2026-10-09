"""au_14: camelCase to snake_case."""
import re
def camel_to_snake(s):
    """Convert camelCase to snake_case."""
    return re.sub(r'(?<!^)(?=[A-Z])', '_', s).lower()

def _run_tests():
    assert camel_to_snake('camelCase') == 'camel_case'
    assert camel_to_snake('A') == 'a'

if __name__ == "__main__":
    _run_tests()
    print("au_14 OK")
