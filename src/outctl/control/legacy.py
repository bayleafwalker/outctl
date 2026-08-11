"""Explicit lazy access to the Python v1 reference implementation.

The control/native namespaces never import this module automatically.  Callers
that intentionally need the compatibility engine can load its adapter on
demand, making the migration boundary visible in code review.
"""

from __future__ import annotations

from importlib import import_module
from types import ModuleType


def load_reference_adapter() -> ModuleType:
    """Load and return the v1 adapter module only when explicitly requested."""
    return import_module("outctl.adapter")


def load_reference_capture() -> ModuleType:
    """Load and return the v1 capture package only when explicitly requested."""
    return import_module("outctl.capture")


__all__ = ["load_reference_adapter", "load_reference_capture"]
