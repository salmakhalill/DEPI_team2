class ScannerError(Exception):
    """Base exception for all core scanning operations"""
    pass

class ScannerTimeoutError(ScannerError):
    """Raised when a specific scan plugin exceeds its allocated time"""
    pass