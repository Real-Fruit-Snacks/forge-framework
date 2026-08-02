"""setuptools glue: install modules/ and labs/ as data files.

Metadata lives in pyproject.toml; this only computes the data file list,
because setuptools' data-files doesn't expand recursive globs.
"""

from pathlib import Path

from setuptools import setup

data_files = []
for top in ("modules", "labs"):
    for f in Path(top).rglob("*"):
        if f.is_file():
            data_files.append((f"share/forge/{f.parent}", [str(f)]))

setup(data_files=data_files)
