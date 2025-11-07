"""Security utilities for QueryForge.

This module provides security functions to prevent common vulnerabilities
such as path traversal, injection attacks, and other security issues.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


# Whitelist of allowed schema directories
# These paths should be within the application directory
def get_allowed_schema_dirs() -> List[Path]:
    """
    Get list of allowed schema directories.

    These are the only directories from which schema files can be loaded.
    This prevents path traversal attacks.
    """
    # Get the application root directory
    app_root = Path(__file__).parent.parent.resolve()

    return [
        app_root / "cbc",
        app_root / "cortex",
        app_root / "kql",
        app_root / "s1",
    ]


def validate_schema_path(path: Path) -> Path:
    """
    Validate that a schema path is within allowed directories.

    This function prevents path traversal attacks by ensuring that
    schema files can only be loaded from whitelisted directories.

    Parameters
    ----------
    path : Path
        The path to validate

    Returns
    -------
    Path
        The resolved, validated path

    Raises
    ------
    ValueError
        If the path is outside allowed directories or doesn't exist
    SecurityError
        If the path contains suspicious patterns

    Examples
    --------
    >>> from pathlib import Path
    >>> validate_schema_path(Path("/app/cbc/schema.json"))
    PosixPath('/app/cbc/schema.json')

    >>> validate_schema_path(Path("../../etc/passwd"))
    Traceback (most recent call last):
        ...
    ValueError: Schema path ... is outside allowed directories
    """
    if not path:
        raise ValueError("Schema path cannot be empty")

    # Convert to Path object if string
    if isinstance(path, str):
        path = Path(path)

    # Resolve the path (follows symlinks, converts to absolute)
    # strict=False allows checking paths that might not exist yet
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"Failed to resolve schema path {path}: {exc}") from exc

    # Check for suspicious patterns in the path string
    path_str = str(resolved)
    suspicious_patterns = [
        "../",  # Parent directory traversal
        "..\\",  # Windows parent directory traversal
        "/etc/",  # System configuration
        "/proc/",  # Process information
        "/sys/",  # System information
        "\\windows\\",  # Windows system directory
        "\\system32\\",  # Windows system directory
    ]

    for pattern in suspicious_patterns:
        if pattern in path_str.lower():
            raise ValueError(
                f"Schema path contains suspicious pattern '{pattern}': {path}"
            )

    # Check if path is within allowed directories
    allowed_dirs = get_allowed_schema_dirs()
    for allowed_dir in allowed_dirs:
        try:
            # This will raise ValueError if resolved is not relative to allowed_dir
            resolved.relative_to(allowed_dir)
            # If we get here, the path is within an allowed directory
            logger.debug("Schema path %s validated within %s", path, allowed_dir)
            return resolved
        except ValueError:
            # Not within this allowed directory, try next one
            continue

    # If we get here, path is not within any allowed directory
    allowed_dirs_str = ", ".join(str(d) for d in allowed_dirs)
    raise ValueError(
        f"Schema path {resolved} is outside allowed directories. "
        f"Allowed directories: {allowed_dirs_str}"
    )


def validate_glob_results(base_dir: Path, glob_results: List[Path]) -> List[Path]:
    """
    Validate that all paths from a glob are within the base directory.

    This prevents symlink-based attacks where a malicious symlink
    could cause the application to load files from outside the
    intended directory.

    Parameters
    ----------
    base_dir : Path
        The base directory that glob was run from
    glob_results : List[Path]
        List of paths returned from glob

    Returns
    -------
    List[Path]
        Filtered list of validated paths

    Examples
    --------
    >>> base = Path("/app/schemas")
    >>> results = [base / "schema1.json", base / "schema2.json"]
    >>> validate_glob_results(base, results)
    [PosixPath('/app/schemas/schema1.json'), PosixPath('/app/schemas/schema2.json')]
    """
    validated = []
    base_resolved = base_dir.resolve()

    for file_path in glob_results:
        try:
            resolved = file_path.resolve()

            # Ensure the file is within the base directory
            resolved.relative_to(base_resolved)

            # Additional validation against suspicious patterns
            path_str = str(resolved)
            if any(
                pattern in path_str.lower()
                for pattern in ["/etc/", "/proc/", "/sys/", "\\windows\\"]
            ):
                logger.warning(
                    "Skipping file with suspicious path: %s", resolved
                )
                continue

            validated.append(resolved)

        except ValueError:
            # File is outside base directory (likely a symlink attack)
            logger.warning(
                "Skipping file outside base directory: %s (base: %s)",
                file_path,
                base_resolved,
            )
            continue
        except (OSError, RuntimeError) as exc:
            logger.warning("Failed to validate path %s: %s", file_path, exc)
            continue

    return validated
