"""Load the plugin root as the importable package ``clearance`` (no install needed)."""

import atexit
import importlib.util
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _load() -> None:
    if "clearance" in sys.modules:
        return
    spec = importlib.util.spec_from_file_location("clearance", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
    module = importlib.util.module_from_spec(spec)
    sys.modules["clearance"] = module
    spec.loader.exec_module(module)


def pytest_configure(config) -> None:
    """Tests never see (or touch) a real Hermes home: point HERMES_HOME at a throwaway directory."""
    scratch = Path(tempfile.mkdtemp(prefix="clearance-hermes-home-"))
    atexit.register(shutil.rmtree, scratch, True)
    os.environ["HERMES_HOME"] = str(scratch)


_load()
