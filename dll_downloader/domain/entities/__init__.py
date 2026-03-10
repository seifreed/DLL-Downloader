"""
Domain Entities

Core business objects that represent the fundamental concepts of the application.
"""

from .dll_file import Architecture, DLLFile, SecurityStatus, normalize_dll_name

__all__ = ["DLLFile", "Architecture", "SecurityStatus", "normalize_dll_name"]
