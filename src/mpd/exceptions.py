"""Custom exceptions for MPD."""
class MPDError(Exception):
    """Base exception for MPD."""
    pass

class DownloadError(MPDError):
    """Failed to download package data."""
    pass

class ExtractionError(MPDError):
    """Failed to extract package contents."""
    pass

class AnalysisError(MPDError):
    """Failed to analyze package."""
    pass
