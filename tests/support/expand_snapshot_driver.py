"""Execute the unchanged expansion suite with its actual pinned runtime modules."""
import json
import os
import sys
import tempfile
from pathlib import Path
root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root))
revision = "e5e5a4a"
if revision:
    import importlib.abc
    import importlib.util
    import subprocess

    class RuntimeModules(importlib.abc.MetaPathFinder, importlib.abc.Loader):
        def find_spec(self, fullname, path=None, target=None):
            if fullname.split(".")[0] not in {"app", "config", "error_handlers", "route_helpers", "services", "routes", "providers", "streaming"}:
                return None
            name = fullname.replace(".", "/")
            for relative, package in [(name + ".py", False), (name + "/__init__.py", True)]:
                result = subprocess.run(["git", "show", revision + ":" + relative], cwd=root, capture_output=True, text=True)
                if result.returncode == 0:
                    spec = importlib.util.spec_from_loader(fullname, self, origin=str(root) + "/" + relative, is_package=package)
                    spec.loader_state = (relative, result.stdout)
                    return spec
            return None

        def create_module(self, spec):
            return None

        def exec_module(self, module):
            relative, source = module.__spec__.loader_state
            module.__file__ = str(root) + "/" + relative
            if module.__spec__.submodule_search_locations is not None:
                module.__path__ = [str(root) + "/" + relative.rsplit("/", 1)[0]]
            exec(compile(source, module.__file__, "exec"), module.__dict__)

    sys.meta_path.insert(0, RuntimeModules())

import subprocess
import pytest
source = subprocess.check_output(["git", "show", revision + ":tests/test_key_controls_expand.py"], cwd=root, text=True)
with tempfile.TemporaryDirectory(prefix="expand-contract-") as directory:
    path = Path(directory) / "test_expand_snapshot.py"
    path.write_text(source)
    raise SystemExit(pytest.main(["-q", str(path)]))
