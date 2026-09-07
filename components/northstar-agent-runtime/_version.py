"""Single source of truth for the runtime version.

Import this module (never re-declare the string) wherever a version is printed
or compared. Releases bump this value together with every component's
``pyproject.toml`` version (the repository test ``tests/test_release.py``
keeps them aligned); ``0.1.0`` is the first tagged release.
"""

__version__ = "0.1.0"
