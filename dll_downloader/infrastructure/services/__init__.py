"""
Infrastructure Services

Implementations of domain service interfaces using external services.
"""

from .virustotal import VirusTotalScanner

__all__ = ["VirusTotalScanner"]
