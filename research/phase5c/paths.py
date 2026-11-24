"""Private paths shared by Phase 5C workers."""

from pathlib import Path


def private(path):
    path = Path(path).resolve()
    if any((parent / ".git").exists() for parent in (path, *path.parents)):
        raise ValueError("Use paths outside Git")
    return path
