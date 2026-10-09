"""Convert snake_case to camelCase."""
def snake_to_camel(name):
    parts = name.split("_")
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])
if __name__ == "__main__":
    assert snake_to_camel("snake_case") == "snakeCase"
    assert snake_to_camel("a_b_c") == "aBC"
    assert snake_to_camel("plain") == "plain"
    print("ok")
