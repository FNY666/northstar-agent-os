"""Convert camelCase to snake_case."""
import re
def camel_to_snake(name):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
if __name__ == "__main__":
    assert camel_to_snake("camelCase") == "camel_case"
    assert camel_to_snake("HTTPRequest") == "h_t_t_p_request"
    assert camel_to_snake("simple") == "simple"
    print("ok")
