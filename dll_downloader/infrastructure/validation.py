"""Shared validation helpers for infrastructure adapters."""

_POSITIVE_INFINITY = float("inf")
_NEGATIVE_INFINITY = float("-inf")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def is_hex_digest(value: object, lengths: tuple[int, ...]) -> bool:
    """Return True when *value* is a hex string of one of the allowed *lengths*."""
    return (
        isinstance(value, str)
        and len(value) in lengths
        and all(character in _HEX_DIGITS for character in value)
    )


def is_finite_number(value: float) -> bool:
    return value == value and value not in (_POSITIVE_INFINITY, _NEGATIVE_INFINITY)


def validate_positive_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("timeout must be a positive number")
    timeout = float(value)
    if not is_finite_number(timeout) or timeout <= 0:
        raise ValueError("timeout must be a positive number")
    return timeout


def validate_non_negative_number(value: object, field_name: str) -> None:
    """Validate that *value* is a finite, non-negative number."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a number")
    if not is_finite_number(value):
        raise ValueError(f"{field_name} must be finite")
    if value < 0:
        raise ValueError(f"{field_name} cannot be negative")
