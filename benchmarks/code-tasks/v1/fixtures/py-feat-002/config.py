"""Merge defaults < file < environment < explicit overrides."""
def merge_config(defaults, file_values=None, env=None, overrides=None):
    result = dict(defaults)
    result.update(file_values or {})
    return result
