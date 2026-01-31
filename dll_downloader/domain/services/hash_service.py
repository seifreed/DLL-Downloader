"""
Hash Calculation Service

Provides centralized hash calculation utilities for the domain layer.
"""

import hashlib


def calculate_sha256(content: bytes) -> str:
    """Calculate SHA256 hash of binary content."""
    return hashlib.sha256(content).hexdigest()
