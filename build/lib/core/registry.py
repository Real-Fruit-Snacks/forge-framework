"""Discovery and loading of modules from one or more module trees.

A file <root>/auxiliary/scanner/port_scan.py becomes the module path
auxiliary/scanner/port_scan. One module class per file. Broken modules
are recorded in `errors` instead of killing the framework.

Multiple roots are merged in order: later roots override earlier ones on
path collision. The framework passes [bundled modules, user modules], so
your ~/.framework/modules copy of a module shadows the bundled one.
"""

import importlib.util
import inspect
import traceback
from pathlib import Path
from typing import Dict, List, Optional, Type, Union

from core import log
from core.module import BaseModule


class ModuleRegistry:
    def __init__(self, roots: Union[str, Path, List[Union[str, Path]]]):
        if isinstance(roots, (str, Path)):
            roots = [roots]
        self.roots: List[Path] = [Path(r) for r in roots]
        # Templates are written to the last (user-writable) root.
        self.modules_root = self.roots[-1]
        self.modules: Dict[str, Type[BaseModule]] = {}
        self.errors: Dict[str, str] = {}

    def load(self) -> None:
        self.modules.clear()
        self.errors.clear()
        for root in self.roots:
            if not root.is_dir():
                continue
            for py_file in sorted(root.rglob("*.py")):
                if py_file.name.startswith("_"):
                    continue
                rel = py_file.relative_to(root).with_suffix("")
                path = "/".join(rel.parts)
                try:
                    self.modules[path] = self._load_file(py_file, path)
                    self.errors.pop(path, None)
                except Exception:
                    self.errors[path] = traceback.format_exc().rstrip()
                    log.get().error(
                        "module load failed: %s\n%s", path, self.errors[path]
                    )

    def _load_file(self, py_file: Path, path: str) -> Type[BaseModule]:
        module_name = "framework_modules." + path.replace("/", ".")
        spec = importlib.util.spec_from_file_location(module_name, py_file)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {py_file}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for _, cls in inspect.getmembers(mod, inspect.isclass):
            # a class actually defined in this file (not an imported base)
            if issubclass(cls, BaseModule) and cls.__module__ == module_name:
                return cls
        raise ValueError(f"no BaseModule subclass defined in {py_file}")

    def get(self, path: str) -> Optional[Type[BaseModule]]:
        return self.modules.get(path)

    def create(self, path: str) -> Optional[BaseModule]:
        """Instantiate a fresh copy of a module by path."""
        cls = self.get(path)
        return cls() if cls else None

    def paths(self, type_dir: Optional[str] = None) -> List[str]:
        if type_dir is None:
            return sorted(self.modules)
        return sorted(p for p in self.modules if p.startswith(type_dir + "/"))

    def search(self, term: str) -> List[str]:
        term = term.lower()
        results = []
        for path in sorted(self.modules):
            cls = self.modules[path]
            haystack = f"{path} {cls.name} {cls.description}".lower()
            if term in haystack:
                results.append(path)
        return results
