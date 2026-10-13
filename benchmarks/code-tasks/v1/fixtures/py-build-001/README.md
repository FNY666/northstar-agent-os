# Package-data fixture

The package exposes `demo_templates.render(name)`, which uses the template
`templates/greeting.txt`. The dependency-free PEP 517 backend reads
`[tool.demo].include-templates` from `pyproject.toml`. Correct that metadata so
an offline wheel build includes resources. Test the installed wheel from a
directory outside the source checkout.
