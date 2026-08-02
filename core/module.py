"""Base classes every module inherits from.

A module file defines exactly one class subclassing AuxiliaryModule,
ExploitModule, or PayloadModule. The registry discovers it, the console
instantiates it on `use`, injects `framework`, and calls run()/generate().

Through `self.framework` a module can reach:
  .sessions        SessionManager -- register shells
  .store           Store          -- persist hosts/services/loot
  .global_options  dict           -- values set with `setg`
"""

import importlib.util
from typing import Any, List, Optional

from core import output
from core.options import OptionContainer


class BaseModule:
    type = "base"
    name = "Unnamed module"
    description = ""
    authors: List[str] = []
    references: List[str] = []
    # Third-party imports this module needs, e.g. ["impacket", "pwntools"].
    # The console refuses to run the module while any are missing.
    requirements: List[str] = []

    def __init__(self) -> None:
        self.options = OptionContainer()
        self.framework: Any = None  # injected by the console
        self.register_options()

    def register_options(self) -> None:
        """Declare options here: self.options.add(OptString("RHOSTS", ...))"""

    def run(self) -> None:
        raise NotImplementedError(f"{type(self).__name__} does not implement run()")

    # -- datastore-style access: module["RHOSTS"] --------------------
    def __setitem__(self, key: str, value: object) -> None:
        self.options[key] = value

    def __getitem__(self, key: str) -> Any:
        return self.options[key]

    def get_option(self, name: str, default: Any = None) -> Any:
        """Module option first, then the global (setg) datastore."""
        key = name.upper()
        if key in self.options:
            val = self.options[key]
            if val is not None:
                return val
        if self.framework is not None:
            return self.framework.global_options.get(key, default)
        return default

    def validate_options(self) -> bool:
        """Check required options (including global fallback). Print + return bool."""
        missing = [
            o.name for o in self.options.options()
            if o.required and self.get_option(o.name) is None
        ]
        for name in missing:
            output.print_error(f"Missing required option: {name}")
        return not missing

    def missing_requirements(self) -> List[str]:
        """Declared requirements that can't be imported right now."""
        missing = []
        for req in type(self).requirements:
            try:
                if importlib.util.find_spec(req) is None:
                    missing.append(req)
            except ModuleNotFoundError:
                missing.append(req)
        return missing

    # -- output helpers, usable from any module ----------------------
    def print_status(self, msg: object) -> None:
        output.print_status(msg)

    def print_good(self, msg: object) -> None:
        output.print_good(msg)

    def print_error(self, msg: object) -> None:
        output.print_error(msg)

    def print_warning(self, msg: object) -> None:
        output.print_warning(msg)

    def print_line(self, msg: object = "") -> None:
        output.print_line(msg)


class AuxiliaryModule(BaseModule):
    """Scanners, fuzzers, info-gathering — anything that runs and returns."""

    type = "auxiliary"


class ExploitModule(BaseModule):
    """Modules that attack a target, optionally yielding a session."""

    type = "exploit"
    targets: List[str] = ["Automatic"]

    def check(self) -> Optional[bool]:
        """Safe, non-destructive vulnerability check.

        Return True (vulnerable), False (not vulnerable), or None (unknown).
        """
        self.print_warning("This module does not implement check()")
        return None


class PayloadModule(BaseModule):
    """Modules that generate a payload string/blob instead of running."""

    type = "payload"

    def generate(self) -> Any:
        raise NotImplementedError(f"{type(self).__name__} does not implement generate()")

    def run(self) -> None:
        result = self.generate()
        if result is not None:
            self.print_line(result)
