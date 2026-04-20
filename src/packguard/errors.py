"""Domain exceptions for Packguard."""


class PackguardError(Exception):
    """Base error for the Packguard application."""


class ConfigError(PackguardError):
    """Raised when configuration cannot be loaded."""


class SourceError(PackguardError):
    """Raised when package metadata cannot be resolved."""


class ExtractionError(PackguardError):
    """Raised when an archive cannot be safely unpacked."""
