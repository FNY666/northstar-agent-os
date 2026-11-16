"""Runtime data files: the files a module reads that are not modules.

The runtime reads two data files at runtime:

* ``dataflow.toml`` -- the default dataflow sensitivity policy, read by
  ``dataflow_policy.py``;
* ``deny_monotonicity_baseline.json`` -- the pinned deny set, read by
  ``deny_monotonicity.py``.

Both live in this directory, and this directory ships in the wheel.
Neither could live in the component root: ``py-modules`` installs ``.py``
files only, so a data file in the component root is in neither installation
mechanism -- it works in the checkout and disappears after
``pip install .``.  The deny-monotonicity baseline has no embedded
fallback and fails closed without it, so on an installed surface it could
never pass.

The package carries no code beyond this docstring: its purpose is to give
``package-data`` a package to name, which is what puts the data files in
the wheel.
"""
from __future__ import annotations

#: The data files this package ships.
DATA_FILES = ("dataflow.toml", "deny_monotonicity_baseline.json")
