"""Shared value-type validation helpers for domain entities and adapters."""

from .entities.dll_file import Architecture


def validate_is_architecture(value: object) -> None:
    """Validate that *value* is an :class:`Architecture` member."""
    if not isinstance(value, Architecture):
        raise ValueError("architecture must be an Architecture")


def validate_is_bool(value: object, field_name: str) -> None:
    """Validate that *value* is a boolean."""
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean")
