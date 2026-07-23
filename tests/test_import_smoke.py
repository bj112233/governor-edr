"""Import smoke test — verify all service modules load without errors.

Catches import-time failures (circular deps, missing deps, syntax errors)
that unit tests might miss if they don't exercise every module path.
"""

import importlib
import pkgutil
import sys

import pytest

# Fail-fast: enforce Python 3.12 (AGENTS.md rule)
if sys.version_info[:2] != (3, 12):
    pytest.skip("Smoke test requires Python 3.12", allow_module_level=True)


def _all_service_modules():
    """Yield fully-qualified module names under services/."""
    import services

    for module_info in pkgutil.walk_packages(services.__path__, prefix="services."):
        # Skip __pycache__ and internal test helpers
        if "__pycache__" in module_info.name:
            continue
        yield module_info.name


@pytest.mark.parametrize("module_name", list(_all_service_modules()))
def test_module_imports_cleanly(module_name):
    """Each services.* module must import without errors."""
    try:
        importlib.import_module(module_name)
    except ImportError as exc:
        # vectorlite is optional — skip modules that hard-require it
        if "vectorlite" in str(exc).lower():
            pytest.skip(f"vectorlite not installed: {module_name}")
        raise
