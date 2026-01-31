"""
Configuration Module

Application configuration and settings management.
This module is part of the infrastructure layer as configuration
reads from external sources (environment variables, files).
"""

from .settings import Settings

__all__ = ["Settings"]
