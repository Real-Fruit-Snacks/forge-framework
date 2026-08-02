"""Shared wordlist and credential helpers for modules."""

from pathlib import Path
from typing import Callable, Iterator, List, Tuple


def load_lines(path) -> List[str]:
    """Lines from a file, skipping blanks and '#' comments."""
    lines = []
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def build_combos(users: List[str], passwords: List[str]) -> Iterator[Tuple[str, str]]:
    """User-major cross product: for each user, every password."""
    for user in users:
        for password in passwords:
            yield (user, password)


def creds_from_options(get: Callable[[str], object], single_opt: str,
                       file_opt: str) -> List[str]:
    """Merge a single-value option and a wordlist-file option into one list.

    `get` is the module's get_option; raises OSError if the file is unreadable.
    """
    values = []
    single = str(get(single_opt) or "").strip()
    if single:
        values.append(single)
    file_path = str(get(file_opt) or "").strip()
    if file_path:
        values.extend(load_lines(file_path))
    return values
