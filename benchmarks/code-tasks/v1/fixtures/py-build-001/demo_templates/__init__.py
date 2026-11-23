"""Read templates using package resources, including from an installed wheel."""
from importlib.resources import files

def render(name):
    template = files(__package__).joinpath("templates/greeting.txt").read_text(encoding="utf-8")
    return template.replace("{name}", name)
