"""Data Flow Analyser package."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("data-flow-analyser")
except PackageNotFoundError:
    __version__ = "unknown"
