"""Shared ZIP archive safety limits and helpers (zip-bomb protection).

These limits are security-sensitive: keeping a single definition prevents the
download and persistence code paths from drifting to inconsistent thresholds.
"""

ZIP_MEMBER_SIZE_LIMIT = 512 * 1024 * 1024  # 512 MiB
ZIP_MEMBER_COUNT_LIMIT = 4096


def zip_member_basename(filename: str) -> str:
    """Return the lowercased basename of a ZIP member, normalising separators."""
    return filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
